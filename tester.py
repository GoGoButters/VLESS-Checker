import asyncio
import json
import logging
import os
import socket
import tempfile
import time
from datetime import datetime, timezone

import httpx
from sqlmodel import Session, select

from database import ProxyResult, Settings, TestUrl, engine
from proxy_parsers import parse_proxy_url, extract_host_port

logger = logging.getLogger("vpn_checker.tester")

SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")

# Global state for test progress
test_status = {
    "running": False,
    "total": 0,
    "checked": 0,
    "passed": 0,
    "failed": 0,
    "current_phase": "idle",
}


def _get_free_port() -> int:
    """Get a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _tcp_ping(host: str, port: int, timeout: float = 3.0) -> int | None:
    """Async TCP ping. Returns latency in ms or None on failure."""
    try:
        start = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        latency = int((time.monotonic() - start) * 1000)
        writer.close()
        await writer.wait_closed()
        return latency
    except Exception:
        return None


def _build_singbox_config(outbound: dict, socks_port: int) -> dict:
    """Build sing-box JSON config for a proxy check."""
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


async def _check_single_proxy(
    proxy_url: str,
    semaphore: asyncio.Semaphore,
    ping_threshold: int,
    http_timeout_s: int,
    test_urls: list[dict],
) -> tuple[str, int, int, int] | None:
    """Check a single proxy against all test URLs."""
    async with semaphore:
        parsed_outbound = parse_proxy_url(proxy_url)
        if not parsed_outbound:
            test_status["checked"] += 1
            test_status["failed"] += 1
            return None

        # Step 1: TCP ping
        target_host = parsed_outbound.get("server", "")
        target_port = parsed_outbound.get("server_port", 443)
        ping = await _tcp_ping(target_host, target_port)
        if ping is None or ping > ping_threshold:
            test_status["checked"] += 1
            test_status["failed"] += 1
            logger.debug(f"TCP ping failed/too slow for {target_host}:{target_port} ({ping}ms)")
            return None

        # Step 2: sing-box subprocess — run all test URL checks through the same proxy instance
        socks_port = _get_free_port()
        config = _build_singbox_config(parsed_outbound, socks_port)

        config_fd, config_path = tempfile.mkstemp(suffix=".json", prefix="sing_")
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
                    test_status["checked"] += 1
                    test_status["failed"] += 1
                    return None

                local_proxy_url = f"socks5://127.0.0.1:{socks_port}"
                tests_total = len(test_urls)
                tests_passed = 0

                # Run each test URL sequentially through the same sing-box instance
                for tu in test_urls:
                    try:
                        use_verify = not tu["url"].endswith("/generate_204")
                        async with httpx.AsyncClient(
                            proxy=local_proxy_url,
                            timeout=httpx.Timeout(float(http_timeout_s)),
                            verify=use_verify,
                            follow_redirects=True,
                        ) as client:
                            resp = await client.get(tu["url"])
                            body_len = len(resp.content)
                            if resp.status_code == tu["expect_status"] and body_len >= tu["min_body_bytes"]:
                                tests_passed += 1
                            else:
                                logger.debug(
                                    f"Test URL {tu['url']} failed for {target_host}:{target_port} "
                                    f"(status={resp.status_code}, expected={tu['expect_status']}, "
                                    f"body={body_len}b, min={tu['min_body_bytes']}b)"
                                )
                    except Exception as e:
                        logger.debug(f"Test URL {tu['url']} error for {target_host}:{target_port}: {e}")

                # A proxy must pass at least 1 test to be saved
                if tests_passed > 0:
                    test_status["checked"] += 1
                    test_status["passed"] += 1
                    logger.info(
                        f"✓ PASS [{ping}ms] {tests_passed}/{tests_total} "
                        f"{target_host}:{target_port}"
                    )
                    return (proxy_url, ping, tests_passed, tests_total)
                else:
                    test_status["checked"] += 1
                    test_status["failed"] += 1
                    return None

            except Exception as e:
                logger.debug(f"Proxy check failed for {target_host}:{target_port}: {e}")
                test_status["checked"] += 1
                test_status["failed"] += 1
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


async def run_full_test(proxy_links: list[str]) -> list[tuple[str, int, int, int]]:
    """Run the full test pipeline on a list of proxy links."""
    # Get settings + test URLs
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        ping_threshold = settings.ping_threshold_ms if settings else 1000
        concurrent_limit = settings.concurrent_checks_limit if settings else 50
        http_timeout_s = settings.http_timeout_s if settings else 10

        test_url_rows = session.exec(select(TestUrl).order_by(TestUrl.position)).all()
        test_urls = [
            {"url": t.url, "expect_status": t.expect_status, "min_body_bytes": t.min_body_bytes}
            for t in test_url_rows
        ]

    if not test_urls:
        logger.warning("No test URLs configured — skipping test")
        return []

    # Deduplicate proxies by EXACT matching string (many CDNs share the same host/port)
    original_count = len(proxy_links)
    proxy_links = list(dict.fromkeys(proxy_links))
    logger.info(f"Deduplication: {len(proxy_links)} unique proxies remaining (from {original_count})")

    test_status["running"] = True
    test_status["total"] = len(proxy_links)
    test_status["checked"] = 0
    test_status["passed"] = 0
    test_status["failed"] = 0
    test_status["current_phase"] = "checking"

    logger.info(
        f"Starting test: {len(proxy_links)} links, {len(test_urls)} test URLs, "
        f"threshold={ping_threshold}ms, concurrency={concurrent_limit}"
    )

    semaphore = asyncio.Semaphore(concurrent_limit)
    tasks = [
        _check_single_proxy(link, semaphore, ping_threshold, http_timeout_s, test_urls)
        for link in proxy_links
    ]
    results = await asyncio.gather(*tasks)

    # Filter successful results
    valid: list[tuple[str, int, int, int]] = [r for r in results if r is not None]

    # Sort: most tests passed first, then lowest ping
    valid.sort(key=lambda x: (-x[2], x[1]))

    # Save to DB
    test_status["current_phase"] = "saving"
    with Session(engine) as session:
        from sqlmodel import delete
        session.exec(delete(ProxyResult))

        now = datetime.now(timezone.utc).isoformat()
        for p_url, ping_ms, passed, total in valid:
            proxy = ProxyResult(
                raw_url=p_url,
                ping_ms=ping_ms,
                tests_passed=passed,
                tests_total=total,
                last_tested=now,
            )
            session.add(proxy)
        session.commit()

    test_status["current_phase"] = "done"
    test_status["running"] = False
    logger.info(f"Test complete: {len(valid)} passed out of {len(proxy_links)}")

    return valid
