"""Speed tester — measures download/upload speed through top-N proxies.

Uses multi-stream downloads from reliable CDN endpoints with streaming
byte counting.  Probes availability via GET+Range instead of HEAD for
maximum compatibility with file servers.
"""

import asyncio
import json
import logging
import os
import socket
import tempfile
import time

import httpx
from sqlmodel import Session, select

from database import ProxyResult, Settings, engine
from proxy_parsers import parse_proxy_url

logger = logging.getLogger("vpn_checker.speed_tester")

SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")

# ---------------------------------------------------------------------------
# Speed test configuration
# ---------------------------------------------------------------------------
# Download URLs ordered by reliability (10 MB files).
# CacheFly is the most reliable CDN globally, followed by Hetzner mirrors.
DL_TEST_URLS = [
    "http://cachefly.cachefly.net/10mb.test",
    "https://speed.hetzner.de/10MB.bin",
    "https://ash-speed.hetzner.com/10MB.bin",
    "https://proof.ovh.net/files/10Mb.dat",
    "http://speedtest.tele2.net/10MB.zip",
]

# Upload endpoints (POST, accept binary body)
UL_TEST_URLS = [
    "https://httpbin.org/post",
    "http://speedtest.tele2.net/upload.php",
]

DL_PARALLEL_STREAMS = 4                 # parallel download connections
DL_MAX_DURATION_S = 12                  # stop after N seconds regardless

# Upload: 2 MB payload
UL_PAYLOAD_SIZE = 2 * 1024 * 1024       # 2 MB


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_singbox_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"disabled": True, "level": "error"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port
            }
        ],
        "outbounds": [
            outbound
        ]
    }


# ---------------------------------------------------------------------------
# Streaming multi-connection download measurement
# ---------------------------------------------------------------------------
async def _download_stream(client: httpx.AsyncClient, url: str,
                           counter: dict, stop_event: asyncio.Event,
                           timeout_s: float) -> None:
    """Download from `url`, streaming bytes and adding to shared counter."""
    try:
        async with client.stream("GET", url, timeout=httpx.Timeout(timeout_s)) as resp:
            if resp.status_code not in (200, 206):
                return
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                if stop_event.is_set():
                    return
                counter["bytes"] += len(chunk)
    except Exception:
        pass


async def _probe_url(client: httpx.AsyncClient, url: str) -> bool:
    """Probe a URL for availability using a small GET+Range request.

    Uses GET with Range header instead of HEAD because many file servers
    (Hetzner, OVH, Tele2) do not support HEAD properly and return
    403/405/other errors.
    """
    try:
        resp = await client.get(
            url,
            headers={"Range": "bytes=0-1023"},
            timeout=httpx.Timeout(8.0),
        )
        # 200 = server ignores Range (full file), 206 = partial content,
        # 301/302 = redirect (follow_redirects handles it)
        if resp.status_code in (200, 206):
            logger.debug(f"Speed probe OK: {url} (status={resp.status_code}, "
                         f"body={len(resp.content)}b)")
            return True
        else:
            logger.debug(f"Speed probe FAIL: {url} (status={resp.status_code})")
            return False
    except Exception as e:
        logger.debug(f"Speed probe ERROR: {url} ({type(e).__name__}: {e})")
        return False


async def _measure_download(proxy_addr: str, timeout_s: int,
                            extra_urls: list[str] | None = None) -> int:
    """Measure download speed using multiple parallel streams.
    Returns download speed in KB/s, or 0 on failure.

    Args:
        extra_urls: Additional download URLs to try (e.g. master panel's
                    self-hosted endpoint). These are tried FIRST.
    """
    counter = {"bytes": 0}
    stop_event = asyncio.Event()

    # Build URL list: extra_urls first (most reliable for restricted networks),
    # then the standard CDN URLs.
    candidate_urls = list(extra_urls or []) + list(DL_TEST_URLS)

    async with httpx.AsyncClient(
        proxy=proxy_addr,
        timeout=httpx.Timeout(float(timeout_s)),
        verify=False,
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=DL_PARALLEL_STREAMS + 2,
            max_keepalive_connections=DL_PARALLEL_STREAMS + 2,
        ),
    ) as client:
        # Find a reachable download URL via small GET probe
        url = None
        for test_url in candidate_urls:
            if await _probe_url(client, test_url):
                url = test_url
                break

        if not url:
            logger.warning("Speed DL: no reachable download URL found after "
                           f"probing {len(candidate_urls)} candidates")
            return 0

        logger.debug(f"Speed DL: using {url}")

        # Launch parallel download streams
        start = time.monotonic()

        async def _auto_stop():
            await asyncio.sleep(DL_MAX_DURATION_S)
            stop_event.set()

        stop_task = asyncio.create_task(_auto_stop())

        tasks = [
            asyncio.create_task(
                _download_stream(client, url, counter, stop_event, float(timeout_s))
            )
            for _ in range(DL_PARALLEL_STREAMS)
        ]

        await asyncio.gather(*tasks, return_exceptions=True)
        stop_event.set()
        stop_task.cancel()

        elapsed = time.monotonic() - start

    if elapsed > 0 and counter["bytes"] > 0:
        return int((counter["bytes"] / 1024) / elapsed)
    return 0


# ---------------------------------------------------------------------------
# Upload measurement
# ---------------------------------------------------------------------------
async def _measure_upload(proxy_addr: str, timeout_s: int) -> int:
    """Measure upload speed by POSTing data to a speed test endpoint.
    Returns upload speed in KB/s, or 0 on failure.
    """
    payload = os.urandom(UL_PAYLOAD_SIZE)

    async with httpx.AsyncClient(
        proxy=proxy_addr,
        timeout=httpx.Timeout(float(timeout_s)),
        verify=False,
        follow_redirects=True,
    ) as client:
        for ul_url in UL_TEST_URLS:
            try:
                start = time.monotonic()
                resp = await client.post(
                    ul_url,
                    content=payload,
                    headers={"Content-Type": "application/octet-stream"},
                )
                elapsed = time.monotonic() - start

                if resp.status_code == 200 and elapsed > 0:
                    return int((UL_PAYLOAD_SIZE / 1024) / elapsed)
            except Exception as e:
                logger.debug(f"Upload to {ul_url} failed: {e}")
                continue

    return 0


# ---------------------------------------------------------------------------
# Combined speed measurement for a single proxy
# ---------------------------------------------------------------------------
async def _measure_speed(proxy_url: str, timeout_s: int = 20,
                         extra_dl_urls: list[str] | None = None) -> tuple[int, int] | None:
    """Measure download/upload speed for a single proxy.
    Returns (download_kbps, upload_kbps) or None on failure.

    Args:
        extra_dl_urls: Extra download URLs to try first (e.g. master panel's
                       self-hosted speed test endpoint).
    """
    parsed_outbound = parse_proxy_url(proxy_url)
    if not parsed_outbound:
        return None

    socks_port = _get_free_port()
    config = _build_singbox_config(parsed_outbound, socks_port)

    config_fd, config_path = tempfile.mkstemp(suffix=".json", prefix="speed_")
    try:
        with os.fdopen(config_fd, "w") as f:
            json.dump(config, f)

        proc = await asyncio.create_subprocess_exec(
            SINGBOX_PATH, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            # Wait for sing-box to start and establish the tunnel
            await asyncio.sleep(1.5)

            if proc.returncode is not None:
                return None

            local_proxy = f"socks5://127.0.0.1:{socks_port}"

            # Download speed test (multi-stream)
            dl_kbps = await _measure_download(local_proxy, timeout_s,
                                              extra_urls=extra_dl_urls)

            # Upload speed test
            ul_kbps = await _measure_upload(local_proxy, timeout_s)

            if dl_kbps > 0:
                return (dl_kbps, ul_kbps)
            return None

        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    finally:
        try:
            os.unlink(config_path)
        except Exception:
            pass


def _compute_speed_score(ping_ms: int, tests_passed: int, dl_kbps: int, ul_kbps: int) -> float:
    """Compute a composite speed score.
    Tests passed is the primary factor, followed by speed (DL+UL), and ping penalty.
    """
    pass_component = tests_passed * 3000.0
    speed_component = (dl_kbps + ul_kbps) * 1.0
    ping_penalty = ping_ms * 0.5
    return max(0.0, pass_component + speed_component - ping_penalty)


async def run_speed_test(test_status: dict) -> None:
    """Run speed tests on top-N proxies and update scores in DB."""
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        top_n = settings.speed_test_top_n if settings else 0
        http_timeout = settings.http_timeout_s if settings else 10

    if top_n <= 0:
        logger.info("Speed test disabled (top_n=0)")
        return

    # Get top-N proxies
    with Session(engine) as session:
        proxies = session.exec(
            select(ProxyResult)
            .order_by(ProxyResult.tests_passed.desc(), ProxyResult.ping_ms)
            .limit(top_n)
        ).all()

    if not proxies:
        logger.info("No proxies to speed-test")
        return

    test_status["current_phase"] = "speed_testing"
    logger.info(f"Starting speed test for top {len(proxies)} proxies (multi-stream, 10MB chunks)")

    semaphore = asyncio.Semaphore(3)  # Max 3 concurrent speed tests (each uses 4 streams)
    results = {}

    async def _test_one(proxy: ProxyResult):
        async with semaphore:
            result = await _measure_speed(proxy.raw_url, timeout_s=max(http_timeout + 5, 20))
            if result:
                dl, ul = result
                score = _compute_speed_score(proxy.ping_ms, proxy.tests_passed, dl, ul)
                results[proxy.raw_url] = (dl, ul, score)
                logger.info(
                    f"⚡ Speed [{proxy.ping_ms}ms] DL={dl}KB/s UL={ul}KB/s "
                    f"Score={score:.0f} — {proxy.raw_url[:80]}..."
                )
            else:
                # Keep existing data, just mark score from tests/ping
                score = _compute_speed_score(proxy.ping_ms, proxy.tests_passed, 0, 0)
                results[proxy.raw_url] = (0, 0, score)

    tasks = [_test_one(p) for p in proxies]
    await asyncio.gather(*tasks)

    # Update DB
    with Session(engine) as session:
        for raw_url, (dl, ul, score) in results.items():
            proxy = session.exec(
                select(ProxyResult).where(ProxyResult.raw_url == raw_url)
            ).first()
            if proxy:
                proxy.download_speed_kbps = dl
                proxy.upload_speed_kbps = ul
                proxy.speed_score = score
                session.add(proxy)
        session.commit()

    logger.info(f"Speed test complete: {len(results)} proxies measured")
