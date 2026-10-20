"""Subscription manager: fetches, parses, and deduplicates VLESS links."""

import base64
import logging
from concurrent.futures import ThreadPoolExecutor

import httpx
from datetime import datetime, timezone
from sqlmodel import Session, select


from database import Subscription, RawProxy, Settings, engine

logger = logging.getLogger("vpn_checker.subs_manager")

# Per-request HTTP budget. Some mirrors (e.g. gitverse.ru) regularly stall for
# 20-32s; fail fast so one slow mirror cannot stretch the whole fetch cycle.
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_FETCH_WORKERS = 5


def _decode_base64(data: str) -> str:
    """Decode base64 string, handling padding."""
    data = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _strip_remark(url: str) -> str:
    """Return URL identity by stripping the #fragment (remark/name).
    Two configs that differ only in their #remark are considered duplicates.
    """
    return url.split("#", 1)[0]


def _extract_proxy_links(text: str, enabled_protocols: dict | None = None) -> list[str]:
    """Extract all supported proxy links from text, filtered by enabled_protocols."""
    PROTOCOL_MAP = {
        "vless": "vless://",
        "vmess": "vmess://",
        "trojan": "trojan://",
        "ss": "ss://",
        "hy2": "hy2://",
        "hysteria2": "hysteria2://",
    }

    # If no filter specified, allow all
    if enabled_protocols is None:
        enabled_protocols = {k: True for k in PROTOCOL_MAP.keys()}

    allowed_prefixes = [prefix for proto, prefix in PROTOCOL_MAP.items() if enabled_protocols.get(proto, True)]

    links = []
    for line in text.split("\n"):
        line = line.strip()
        if any(line.startswith(p) for p in allowed_prefixes):
            links.append(line)
    return links


def _fetch_one(client: httpx.Client, url: str, enabled_protocols: dict | None) -> tuple[str, list[str]]:
    """Fetch a single subscription URL. Returns (url, links). Never raises."""
    try:
        logger.info(f"Fetching subscription: {url}")
        resp = client.get(url)
        resp.raise_for_status()
        raw_text = resp.text.strip()

        # Try base64 decode first, fall back to raw text
        decoded = _decode_base64(raw_text)
        links = _extract_proxy_links(decoded, enabled_protocols)
        if not links:
            links = _extract_proxy_links(raw_text, enabled_protocols)
        return url, links
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return url, []


def fetch_and_parse_subscriptions_sync(
    session=None, enabled_protocols: dict | None = None
) -> list[str]:
    """Synchronously fetch all subscription URLs and extract unique proxy links.

    Blocking on purpose: callers run this off the event loop
    (``asyncio.to_thread``). Subscriptions are fetched in parallel so a single
    slow mirror no longer serializes the whole cycle.

    If ``session`` is provided, updates ``last_config_count`` per subscription
    and skips disabled subscriptions. Excludes currently banned proxies.
    """
    with Session(engine) as local_session:
        if session is None:
            subs = local_session.exec(select(Subscription)).all()
        else:
            subs = session.exec(select(Subscription)).all()

    # Get banned proxies — simply check if banned_until > now
    banned_urls = set()
    if session is not None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with Session(engine) as ban_session:
            # Read ban_duration from settings to check if bans are enabled
            settings = ban_session.exec(select(Settings)).first()
            ban_enabled = settings and settings.ban_duration_hours > 0

            if ban_enabled:
                banned = ban_session.exec(
                    select(RawProxy.raw_url).where(RawProxy.banned_until > now_iso)
                ).all()
                # Handle both tuple and scalar results from SQLModel
                for row in banned:
                    url = row[0] if isinstance(row, tuple) else row
                    banned_urls.add(url)
                if banned_urls:
                    logger.info(f"Excluding {len(banned_urls)} currently banned proxies")

    # Skip disabled subscriptions only in the full fetch flow (session provided)
    active_subs = [
        sub for sub in subs
        if session is None or sub.is_enabled
    ]
    for sub in subs:
        if session is not None and not sub.is_enabled:
            logger.info(f"Skipping disabled subscription: {sub.url}")

    all_proxies: list[str] = []
    sub_proxy_counts: dict[str, int] = {}
    fetched: list[tuple[str, list[str]]] = []

    if active_subs:
        with httpx.Client(
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:
            with ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as pool:
                fetched = list(pool.map(
                    lambda sub: _fetch_one(client, sub.url, enabled_protocols),
                    active_subs,
                ))

    for sub_url, proxy_links in fetched:
        if proxy_links:
            # Filter out banned proxies
            filtered = [url for url in proxy_links if url not in banned_urls]
            if len(filtered) < len(proxy_links):
                logger.info(f"Filtered out {len(proxy_links) - len(filtered)} banned proxies from {sub_url}")
            all_proxies.extend(filtered)
            sub_proxy_counts[sub_url] = len(filtered)
            logger.info(f"Found {len(filtered)} proxy links in {sub_url}")
        else:
            sub_proxy_counts[sub_url] = 0

    # Update last_config_count if session is provided
    if session is not None:
        for sub in subs:
            if sub.url in sub_proxy_counts:
                sub.last_config_count = sub_proxy_counts[sub.url]
        session.add_all(subs)
        session.commit()

    # Deduplicate by identity key (URL minus #remark)
    seen: dict[str, str] = {}
    duplicates_skipped = 0
    for url in all_proxies:
        key = _strip_remark(url)
        if key not in seen:
            seen[key] = url
        else:
            duplicates_skipped += 1
    unique = list(seen.values())
    if duplicates_skipped > 0:
        logger.info(f"Deduplication: skipped {duplicates_skipped} duplicate configs (same config, different #remark)")
    logger.info(f"Total unique proxy links: {len(unique)}")
    return unique


async def fetch_and_parse_subscriptions(
    session=None, enabled_protocols: dict | None = None
) -> list[str]:
    """Async wrapper — runs the blocking fetch in a worker thread.

    Kept for backwards compatibility; new code should call the sync version from
    inside an existing ``asyncio.to_thread`` block.
    """
    import asyncio
    return await asyncio.to_thread(
        fetch_and_parse_subscriptions_sync, session, enabled_protocols
    )
