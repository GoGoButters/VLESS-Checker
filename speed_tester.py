"""Download/upload speed through a proxy (worker nodes)."""
from __future__ import annotations

import asyncio
import logging
import os
import time

import httpx

from engine_driver import start_engine
from proxy_parsers import parse_proxy_url

logger = logging.getLogger("vpn_checker.speed_tester")

# 10 MB files, most reliable first; the master's own endpoint is tried before these.
DL_TEST_URLS = [
    "http://cachefly.cachefly.net/10mb.test",
    "https://ash-speed.hetzner.com/10MB.bin",
    "https://proof.ovh.net/files/10Mb.dat",
    "http://speedtest.tele2.net/10MB.zip",
]
UL_TEST_URLS = [
    "https://httpbin.org/post",
    "http://speedtest.tele2.net/upload.php",
]
DL_PARALLEL_STREAMS = 4
DL_MAX_DURATION_S = 12
UL_PAYLOAD_SIZE = 2 * 1024 * 1024
_UL_PAYLOAD = os.urandom(UL_PAYLOAD_SIZE)


# The URL that worked last time is tried first (dead CDNs cost a probe timeout each).
_last_good_url: str | None = None


async def _probe(client: httpx.AsyncClient, url: str) -> bool:
    """Small ranged GET (many file servers mishandle HEAD)."""
    try:
        resp = await client.get(url, headers={"Range": "bytes=0-1023"}, timeout=httpx.Timeout(5.0))
        return resp.status_code in (200, 206)
    except (httpx.HTTPError, OSError):
        return False


async def _download_stream(client: httpx.AsyncClient, url: str, counter: list, stop_at: float) -> None:
    try:
        async with client.stream("GET", url) as resp:
            if resp.status_code not in (200, 206):
                return
            async for chunk in resp.aiter_bytes(65536):
                counter[0] += len(chunk)
                if time.monotonic() >= stop_at:
                    return
    except (httpx.HTTPError, OSError):
        pass


async def measure_download(proxy: str, timeout_s: float, extra_urls: list[str] | None = None) -> int:
    """KB/s over parallel streams, 0 on failure."""
    global _last_good_url
    candidates = list(dict.fromkeys(([_last_good_url] if _last_good_url else []) + list(extra_urls or []) + DL_TEST_URLS))
    async with httpx.AsyncClient(proxy=proxy, timeout=httpx.Timeout(timeout_s), verify=False,
                                 follow_redirects=True,
                                 limits=httpx.Limits(max_connections=DL_PARALLEL_STREAMS + 2)) as client:
        url = None
        for candidate in candidates:
            if await _probe(client, candidate):
                url = _last_good_url = candidate
                break
        if not url:
            return 0
        counter = [0]
        start = time.monotonic()
        stop_at = start + DL_MAX_DURATION_S
        await asyncio.wait_for(
            asyncio.gather(*(_download_stream(client, url, counter, stop_at) for _ in range(DL_PARALLEL_STREAMS))),
            timeout=DL_MAX_DURATION_S + timeout_s,
        )
        elapsed = time.monotonic() - start
    return int(counter[0] / 1024 / elapsed) if elapsed > 0 and counter[0] else 0


async def measure_upload(proxy: str, timeout_s: float) -> int:
    """KB/s for a 2 MB POST, 0 on failure."""
    async with httpx.AsyncClient(proxy=proxy, timeout=httpx.Timeout(timeout_s), verify=False,
                                 follow_redirects=True) as client:
        for url in UL_TEST_URLS:
            try:
                start = time.monotonic()
                resp = await client.post(url, content=_UL_PAYLOAD,
                                         headers={"Content-Type": "application/octet-stream"})
                elapsed = time.monotonic() - start
                if resp.status_code == 200 and elapsed > 0:
                    return int(UL_PAYLOAD_SIZE / 1024 / elapsed)
            except (httpx.HTTPError, OSError):
                continue
    return 0


async def measure_speed(proxy_url: str, timeout_s: float = 20,
                        extra_dl_urls: list[str] | None = None) -> tuple[int, int] | None:
    """(download KB/s, upload KB/s) or None. Bounded by a hard deadline."""
    outbound = parse_proxy_url(proxy_url)
    if not outbound:
        return None
    handle = await start_engine(outbound, wait_s=float(os.environ.get("ENGINE_START_WAIT_S", "4")))
    if handle is None:
        return None
    proxy = f"socks5://127.0.0.1:{handle.socks_port}"
    try:
        async def _both():
            dl = await measure_download(proxy, timeout_s, extra_dl_urls)
            ul = await measure_upload(proxy, timeout_s) if dl else 0
            return dl, ul
        dl, ul = await asyncio.wait_for(_both(), timeout=DL_MAX_DURATION_S + 3 * timeout_s + 10)
        return (dl, ul) if dl > 0 else None
    except (asyncio.TimeoutError, httpx.HTTPError, OSError):
        return None
    finally:
        await handle.stop()


def compute_speed_score(ping_ms: int, tests_passed: int, dl_kbps: int, ul_kbps: int) -> float:
    """Tests passed dominate, then DL+UL speed, minus a ping penalty."""
    return max(0.0, tests_passed * 3000.0 + (dl_kbps + ul_kbps) - ping_ms * 0.5)
