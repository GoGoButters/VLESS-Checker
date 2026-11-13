"""Subscription sources: fetch, decode, extract links, keep the last good snapshot.

A source is downloaded at most once per fetch cycle even when several groups
use it. A failed or empty download keeps the previous snapshot, so a flaky
mirror can not wipe the pools of the groups built from it.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, wait

import httpx

from proxy_parsers import ALL_PREFIXES, protocol_of, proxy_key

logger = logging.getLogger("vpn_checker.sources")

HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
REQUEST_DEADLINE_S = 60          # one download, however slowly it trickles
CYCLE_DEADLINE_S = 180           # all downloads of one cycle
MAX_BODY_BYTES = 20 * 1024 * 1024
MAX_FETCH_WORKERS = 8
USER_AGENT = "v2rayN/7.0 (VPN-Checker)"


# ---------------------------------------------------------------------------
# content → links
# ---------------------------------------------------------------------------
def _maybe_base64(text: str) -> str | None:
    compact = "".join(text.split())
    if not compact or len(compact) % 4 == 1 or "://" in compact[:64]:
        return None
    try:
        compact = compact.replace("-", "+").replace("_", "/")
        out = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return out if "://" in out else None


def _clash_to_links(text: str) -> list[str]:
    """Convert a Clash/Mihomo YAML `proxies:` list into share links."""
    try:
        import yaml
        data = yaml.safe_load(text)
    except Exception:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), list):
        return []
    from clash_convert import clash_proxy_to_link
    links = []
    for p in data["proxies"]:
        if isinstance(p, dict):
            link = clash_proxy_to_link(p)
            if link:
                links.append(link)
    return links


def _json_strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        obj = list(obj.values())
    if isinstance(obj, list):
        return [s for item in obj for s in _json_strings(item)]
    return []


def extract_links(text: str) -> list[str]:
    """All share links in a subscription body: plain, base64, Clash YAML, or
    JSON carrying them in string values (e.g. {"data": "vless://…\\nvless://…"})."""
    text = (text or "").lstrip("﻿").strip()
    if not text:
        return []
    if text[0] in "{[":
        try:
            values = _json_strings(json.loads(text))
        except ValueError:
            values = None
        if values is not None:
            return [link for value in values for link in extract_links(value)]
    decoded = _maybe_base64(text)
    if decoded:
        text = decoded
    elif "proxies:" in text[:20000] and "://" not in text[:200]:
        return _clash_to_links(text)
    links = []
    for line in text.splitlines():
        line = line.strip()
        if line[:16].lower().startswith(ALL_PREFIXES):
            links.append(line)
    return links


def filter_protocols(links: list[str], enabled: dict) -> list[str]:
    return [u for u in links if enabled.get(protocol_of(u) or "", False)]


def source_signature(links: list[str]) -> str:
    """Identity of a source's set of configs (order and #remarks ignored).
    Same definition as v1 so autoskip state survives the migration."""
    ids = sorted({u.split("#", 1)[0] for u in links if u})
    return hashlib.sha1("\n".join(ids).encode("utf-8")).hexdigest() if ids else ""


def dedup(links: list[str]) -> dict[str, str]:
    """key → first link with that key."""
    out: dict[str, str] = {}
    for u in links:
        out.setdefault(proxy_key(u), u)
    return out


# ---------------------------------------------------------------------------
# snapshots
# ---------------------------------------------------------------------------
def pack_links(links: list[str]) -> bytes:
    return zlib.compress("\n".join(links).encode("utf-8"), 6)


def unpack_links(blob: bytes | None) -> list[str]:
    if not blob:
        return []
    try:
        return zlib.decompress(blob).decode("utf-8").split("\n")
    except (zlib.error, UnicodeDecodeError):
        return []


# ---------------------------------------------------------------------------
# fetching
# ---------------------------------------------------------------------------
def fetch_one(client: httpx.Client, url: str) -> tuple[list[str] | None, str]:
    """(links, "") on success, (None, error) on failure. Never raises."""
    start = time.monotonic()
    try:
        with client.stream("GET", url) as resp:
            if resp.status_code >= 400:
                return None, f"HTTP {resp.status_code}"
            body = bytearray()
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_BODY_BYTES:
                    return None, "body too large"
                if time.monotonic() - start > REQUEST_DEADLINE_S:
                    return None, "download too slow"
            text = bytes(body).decode(resp.encoding or "utf-8", errors="ignore")
    except (httpx.HTTPError, OSError, ValueError) as e:
        return None, f"{type(e).__name__}: {e}"[:300]
    links = extract_links(text)
    if not links:
        return None, "no proxy links in response"
    return links, ""


def fetch_many(sources: list[tuple[int, str]]) -> dict[int, tuple[list[str] | None, str]]:
    """Fetch sources in parallel under a cycle-wide deadline."""
    results: dict[int, tuple[list[str] | None, str]] = {}
    if not sources:
        return results
    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True, verify=False,
                      headers={"User-Agent": USER_AGENT}) as client:
        pool = ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS, thread_name_prefix="fetch")
        futures = {pool.submit(fetch_one, client, url): sid for sid, url in sources}
        done, pending = wait(futures, timeout=CYCLE_DEADLINE_S)
        for fut in done:
            results[futures[fut]] = fut.result()
        for fut in pending:
            fut.cancel()
            results[futures[fut]] = (None, "cycle deadline exceeded")
        # Don't wait for stragglers: their own REQUEST_DEADLINE_S ends them.
        pool.shutdown(wait=False, cancel_futures=True)
    ok = sum(1 for links, _ in results.values() if links)
    logger.info(f"Fetched {len(sources)} sources: {ok} ok, {len(sources) - ok} failed")
    return results
