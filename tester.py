"""VLESS proxy tester using xray-core subprocess and async HTTP checks."""

import asyncio
import json
import logging
import os
import socket
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import unquote

import httpx
from sqlmodel import Session, select

from database import ValidProxy, Settings, TestUrl, engine

logger = logging.getLogger("vpn_checker.tester")

XRAY_PATH = os.environ.get("XRAY_PATH", "/usr/local/bin/xray")

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


def _parse_vless_url(vless_url: str) -> dict | None:
    """Parse a vless:// URL into components."""
    try:
        if not vless_url.startswith("vless://"):
            return None
        url = vless_url[8:]  # remove vless://

        # Split user@host:port and fragment
        at_idx = url.index("@")
        uuid = url[:at_idx]

        rest = url[at_idx + 1:]

        # Extract fragment (remark)
        remark = ""
        if "#" in rest:
            rest, remark = rest.rsplit("#", 1)
            remark = unquote(remark)

        # Extract query params
        params = {}
        if "?" in rest:
            host_port, query = rest.split("?", 1)
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        else:
            host_port = rest

        # Parse host:port  (handle IPv6 [::1]:443)
        if host_port.startswith("["):
            bracket_end = host_port.index("]")
            host = host_port[1:bracket_end]
            port = int(host_port[bracket_end + 2:])
        else:
            parts = host_port.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443

        return {
            "uuid": uuid,
            "host": host,
            "port": port,
            "remark": remark,
            "params": params,
        }
    except Exception as e:
        logger.debug(f"Failed to parse VLESS URL: {e}")
        return None


def _replace_vless_remark(vless_url: str, new_remark: str) -> str:
    """Replace the #fragment (remark) in a VLESS URL with a new value."""
    if "#" in vless_url:
        base = vless_url.rsplit("#", 1)[0]
    else:
        base = vless_url
    return f"{base}#{new_remark}"


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


def _build_xray_config(vless_url: str, parsed: dict, socks_port: int) -> dict:
    """Build xray JSON config for a single VLESS proxy check."""
    params = parsed["params"]
    security = params.get("security", "none")
    net_type = params.get("type", "tcp")

    # Build stream settings
    stream_settings: dict = {"network": net_type}

    # TLS / Reality settings
    if security == "tls":
        tls_settings: dict = {
            "serverName": params.get("sni", parsed["host"]),
            "allowInsecure": True,
        }
        fp = params.get("fp", "")
        if fp:
            tls_settings["fingerprint"] = fp
        alpn = params.get("alpn", "")
        if alpn:
            tls_settings["alpn"] = unquote(alpn).split(",")
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = tls_settings

    elif security == "reality":
        reality_settings: dict = {
            "serverName": params.get("sni", ""),
            "fingerprint": params.get("fp", "chrome"),
            "publicKey": params.get("pbk", ""),
            "shortId": params.get("sid", ""),
            "spiderX": params.get("spx", ""),
        }
        stream_settings["security"] = "reality"
        stream_settings["realitySettings"] = reality_settings
    else:
        stream_settings["security"] = "none"

    # Network-specific settings
    if net_type == "ws":
        ws_path = unquote(params.get("path", "/"))
        ws_host = params.get("host", parsed["host"])
        stream_settings["wsSettings"] = {
            "path": ws_path,
            "headers": {"Host": ws_host},
        }
    elif net_type == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": params.get("serviceName", ""),
            "multiMode": params.get("mode", "gun") == "multi",
        }
    elif net_type == "tcp":
        header_type = params.get("headerType", "none")
        if header_type == "http":
            tcp_host = params.get("host", parsed["host"])
            tcp_path = unquote(params.get("path", "/"))
            stream_settings["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [tcp_path],
                        "headers": {"Host": [tcp_host]},
                    },
                }
            }
    elif net_type == "h2" or net_type == "http":
        h2_host = params.get("host", parsed["host"])
        h2_path = unquote(params.get("path", "/"))
        stream_settings["httpSettings"] = {
            "host": [h2_host],
            "path": h2_path,
        }

    # Build full xray config
    flow = params.get("flow", "")
    outbound_settings: dict = {
        "vnext": [{
            "address": parsed["host"],
            "port": parsed["port"],
            "users": [{
                "id": parsed["uuid"],
                "encryption": params.get("encryption", "none"),
            }],
        }]
    }

    if flow:
        outbound_settings["vnext"][0]["users"][0]["flow"] = flow

    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "tag": "socks-in",
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "udp": False,
            },
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "vless",
            "settings": outbound_settings,
            "streamSettings": stream_settings,
        }],
    }

    return config


async def _check_single_proxy(
    vless_url: str,
    semaphore: asyncio.Semaphore,
    ping_threshold: int,
    http_timeout_s: int,
    test_urls: list[dict],
) -> tuple[str, int, int, int] | None:
    """Check a single VLESS proxy against all test URLs.

    Returns (vless_url, ping_ms, tests_passed, tests_total) or None if TCP ping fails.
    A proxy is considered valid if it passes at least 1 test URL.
    """
    async with semaphore:
        parsed = _parse_vless_url(vless_url)
        if not parsed:
            test_status["checked"] += 1
            test_status["failed"] += 1
            return None

        # Step 1: TCP ping
        ping = await _tcp_ping(parsed["host"], parsed["port"])
        if ping is None or ping > ping_threshold:
            test_status["checked"] += 1
            test_status["failed"] += 1
            logger.debug(f"TCP ping failed/too slow for {parsed['host']}:{parsed['port']} ({ping}ms)")
            return None

        # Step 2: xray subprocess — run all test URL checks through the same proxy instance
        socks_port = _get_free_port()
        config = _build_xray_config(vless_url, parsed, socks_port)

        config_fd, config_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
        try:
            with os.fdopen(config_fd, "w") as f:
                json.dump(config, f)

            proc = await asyncio.create_subprocess_exec(
                XRAY_PATH, "run", "-c", config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            try:
                await asyncio.sleep(1.0)

                if proc.returncode is not None:
                    test_status["checked"] += 1
                    test_status["failed"] += 1
                    return None

                proxy_url = f"socks5://127.0.0.1:{socks_port}"
                tests_total = len(test_urls)
                tests_passed = 0

                # Run each test URL sequentially through the same xray instance
                for tu in test_urls:
                    try:
                        use_verify = not tu["url"].endswith("/generate_204")
                        async with httpx.AsyncClient(
                            proxy=proxy_url,
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
                                    f"Test URL {tu['url']} failed for {parsed['host']}:{parsed['port']} "
                                    f"(status={resp.status_code}, expected={tu['expect_status']}, "
                                    f"body={body_len}b, min={tu['min_body_bytes']}b)"
                                )
                    except Exception as e:
                        logger.debug(f"Test URL {tu['url']} error for {parsed['host']}:{parsed['port']}: {e}")

                # A proxy must pass at least 1 test to be saved
                if tests_passed > 0:
                    test_status["checked"] += 1
                    test_status["passed"] += 1
                    remark = parsed.get("remark", "")[:30]
                    logger.info(
                        f"✓ PASS [{ping}ms] {tests_passed}/{tests_total} "
                        f"{parsed['host']}:{parsed['port']} {remark}"
                    )
                    return (vless_url, ping, tests_passed, tests_total)
                else:
                    test_status["checked"] += 1
                    test_status["failed"] += 1
                    return None

            except Exception as e:
                logger.debug(f"Proxy check failed for {parsed['host']}:{parsed['port']}: {e}")
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


async def run_full_test(vless_links: list[str]) -> list[tuple[str, int, int, int]]:
    """Run the full test pipeline on a list of VLESS links.

    Returns list of (vless_url, ping_ms, tests_passed, tests_total).
    """
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

    test_status["running"] = True
    test_status["total"] = len(vless_links)
    test_status["checked"] = 0
    test_status["passed"] = 0
    test_status["failed"] = 0
    test_status["current_phase"] = "checking"

    logger.info(
        f"Starting test: {len(vless_links)} links, {len(test_urls)} test URLs, "
        f"threshold={ping_threshold}ms, concurrency={concurrent_limit}"
    )

    semaphore = asyncio.Semaphore(concurrent_limit)
    tasks = [
        _check_single_proxy(link, semaphore, ping_threshold, http_timeout_s, test_urls)
        for link in vless_links
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
        session.exec(delete(ValidProxy))
        session.commit()

        now = datetime.now(timezone.utc).isoformat()
        for vless_url, ping_ms, passed, total in valid:
            proxy = ValidProxy(
                raw_vless=vless_url,
                ping_ms=ping_ms,
                tests_passed=passed,
                tests_total=total,
                last_tested=now,
            )
            session.add(proxy)
        session.commit()

    test_status["current_phase"] = "done"
    test_status["running"] = False
    logger.info(f"Test complete: {len(valid)} passed out of {len(vless_links)}")

    return valid
