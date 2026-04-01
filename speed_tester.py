"""Speed tester — measures download/upload speed through top-N proxies."""

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

# 1MB test file for speed measurement
SPEED_TEST_DOWNLOAD_URL = "https://proof.ovh.net/files/1Mb.dat"
SPEED_TEST_UPLOAD_BYTES = 256 * 1024  # 256KB upload test payload


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
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ]
    }


async def _measure_speed(proxy_url: str, timeout_s: int = 15) -> tuple[int, int] | None:
    """Measure download/upload speed for a single proxy.
    Returns (download_kbps, upload_kbps) or None on failure.
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
            await asyncio.sleep(1.0)

            if proc.returncode is not None:
                return None

            local_proxy = f"socks5://127.0.0.1:{socks_port}"

            # Download speed test
            dl_kbps = 0
            try:
                async with httpx.AsyncClient(
                    proxy=local_proxy,
                    timeout=httpx.Timeout(float(timeout_s)),
                    verify=True,
                    follow_redirects=True,
                ) as client:
                    start = time.monotonic()
                    resp = await client.get(SPEED_TEST_DOWNLOAD_URL)
                    elapsed = time.monotonic() - start
                    if resp.status_code == 200 and elapsed > 0:
                        bytes_received = len(resp.content)
                        dl_kbps = int((bytes_received / 1024) / elapsed)
            except Exception as e:
                logger.debug(f"Download speed test failed: {e}")

            # Upload speed test
            ul_kbps = 0
            try:
                upload_data = os.urandom(SPEED_TEST_UPLOAD_BYTES)
                async with httpx.AsyncClient(
                    proxy=local_proxy,
                    timeout=httpx.Timeout(float(timeout_s)),
                    verify=True,
                    follow_redirects=True,
                ) as client:
                    start = time.monotonic()
                    # POST to httpbin-style endpoint
                    resp = await client.post(
                        "https://httpbin.org/post",
                        content=upload_data,
                        headers={"Content-Type": "application/octet-stream"},
                    )
                    elapsed = time.monotonic() - start
                    if resp.status_code == 200 and elapsed > 0:
                        ul_kbps = int((SPEED_TEST_UPLOAD_BYTES / 1024) / elapsed)
            except Exception as e:
                logger.debug(f"Upload speed test failed: {e}")

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
    Speed (DL+UL) has 2x weight vs test pass count.
    Lower ping is better — subtract a penalty.
    """
    speed_component = (dl_kbps + ul_kbps) * 2.0
    pass_component = tests_passed * 100.0
    ping_penalty = ping_ms * 0.5
    return max(0.0, speed_component + pass_component - ping_penalty)


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
    logger.info(f"Starting speed test for top {len(proxies)} proxies")

    semaphore = asyncio.Semaphore(5)  # Max 5 concurrent speed tests (heavy)
    results = {}

    async def _test_one(proxy: ProxyResult):
        async with semaphore:
            result = await _measure_speed(proxy.raw_url, timeout_s=http_timeout + 5)
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
