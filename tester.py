"""Proxy checks on worker nodes: TCP ping → engine → test URLs through it.

Every check runs under a hard deadline, so a tunnel that trickles bytes (or a
server that never answers) can not hold a concurrency slot forever — that used
to stall whole test cycles while heartbeats kept the node looking healthy.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import time

import httpx

from engine_driver import ssl_context, start_engine
from proxy_parsers import parse_proxy_url

logger = logging.getLogger("vpn_checker.tester")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


# TCP_PING_GATE=0 keeps proxies whose TCP handshake fails (networks where the
# handshake to the server is flaky); the tunnel test decides instead.
PING_GATE = os.environ.get("TCP_PING_GATE", "1").lower() not in ("0", "false", "no", "off")
PING_TIMEOUT_S = _env_float("TCP_PING_TIMEOUT_S", 3)
PING_THRESHOLD_OVERRIDE = int(_env_float("PING_THRESHOLD_MS_OVERRIDE", 0))
ENGINE_START_WAIT_S = _env_float("ENGINE_START_WAIT_S", 4)
TEST_URL_RETRIES = max(1, int(_env_float("TEST_URL_RETRIES", 2)))
MAX_CONSECUTIVE_FAILURES = max(1, int(_env_float("MAX_CONSECUTIVE_FAILURES", 3)))
# Total time budget for the test URLs of one proxy.
PROXY_TIME_BUDGET_S = _env_float("PROXY_TIME_BUDGET_S", 30)
CONCURRENT_OVERRIDE = int(_env_float("CONCURRENT_CHECKS_OVERRIDE", 0))
# Read at most this much of a test URL body (only min_body_bytes matters).
MAX_BODY_BYTES = 256 * 1024

# QUIC/UDP-based protocols: a TCP ping to their port means nothing.
UDP_PROTOCOLS = {"hysteria2", "hysteria", "tuic"}
UDP_TRANSPORTS = {"kcp", "quic"}


def _bind_interface() -> str:
    return os.environ.get("BIND_INTERFACE", "")


async def tcp_ping(host: str, port: int, timeout: float = 3.0) -> int | None:
    """TCP connect latency in ms through BIND_INTERFACE (if set), else None."""
    iface = _bind_interface()
    loop = asyncio.get_running_loop()
    start = time.monotonic()
    sock = None
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=timeout)
        family, stype, proto, _, addr = infos[0]
        sock = socket.socket(family, stype, proto)
        sock.setblocking(False)
        if iface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
            except (OSError, AttributeError):
                pass  # no CAP_NET_RAW: fall back to the routing table
        remaining = max(0.1, timeout - (time.monotonic() - start))
        await asyncio.wait_for(loop.sock_connect(sock, addr), timeout=remaining)
        return max(1, int((time.monotonic() - start) * 1000))
    except (OSError, asyncio.TimeoutError, IndexError):
        return None
    finally:
        if sock is not None:
            sock.close()


async def _fetch(client: httpx.AsyncClient, tu: dict, timeout: float) -> tuple[bool, str, float]:
    """GET one test URL; reads only as much body as min_body_bytes requires."""
    need = max(0, int(tu.get("min_body_bytes") or 0))
    start = time.monotonic()

    async def _do() -> tuple[bool, str]:
        async with client.stream("GET", tu["url"]) as resp:
            got = 0
            if need:
                async for chunk in resp.aiter_bytes():
                    got += len(chunk)
                    if got >= need or got >= MAX_BODY_BYTES:
                        break
            ok = resp.status_code == tu["expect_status"] and got >= need
            return ok, f"status={resp.status_code} (want {tu['expect_status']}), body>={got}b (min {need}b)"

    try:
        ok, info = await asyncio.wait_for(_do(), timeout=timeout)
    except asyncio.TimeoutError:
        ok, info = False, f"timeout {timeout:.0f}s"
    except (httpx.HTTPError, OSError, ValueError) as e:
        ok, info = False, f"{type(e).__name__}: {e}"
    return ok, info, time.monotonic() - start


async def run_test_urls(socks_port: int, test_urls: list[dict], http_timeout_s: float,
                        label: str, deadline: float) -> tuple[int, int, int]:
    """Test URLs through a local SOCKS port → (passed, total, first_ok_ms).

    Each URL gets TEST_URL_RETRIES attempts (a fresh tunnel often drops the
    first request); MAX_CONSECUTIVE_FAILURES in a row stop the run early.
    """
    total = len(test_urls)
    passed = 0
    consecutive = 0
    first_ok_ms = 0
    async with httpx.AsyncClient(
        proxy=f"socks5://127.0.0.1:{socks_port}",
        timeout=httpx.Timeout(http_timeout_s),
        verify=ssl_context(True),
        follow_redirects=True,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
    ) as client:
        for tu in test_urls:
            ok, info = False, ""
            for _ in range(TEST_URL_RETRIES):
                left = deadline - time.monotonic()
                if left <= 1:
                    info = "time budget exhausted"
                    break
                ok, info, took = await _fetch(client, tu, min(float(http_timeout_s), left))
                if ok:
                    if not first_ok_ms:
                        first_ok_ms = max(1, int(took * 1000))
                    break
            if ok:
                passed += 1
                consecutive = 0
                continue
            consecutive += 1
            logger.debug(f"{label}: {tu['url']} failed: {info}")
            if consecutive >= MAX_CONSECUTIVE_FAILURES or deadline - time.monotonic() <= 1:
                break
    return passed, total, first_ok_ms


async def check_proxy(proxy_url: str, test_urls: list[dict], ping_threshold_ms: int,
                      http_timeout_s: float) -> dict:
    """Full check of one proxy. Never raises; returns a result dict."""
    result = {"raw_url": proxy_url, "ping_ms": 0, "tests_passed": 0, "tests_total": len(test_urls)}
    outbound = parse_proxy_url(proxy_url)
    if not outbound:
        return result
    host = outbound.get("server", "")
    port = int(outbound.get("server_port") or 443)

    ping = None
    over_udp = (outbound.get("type") in UDP_PROTOCOLS
                or (outbound.get("transport") or {}).get("type") in UDP_TRANSPORTS)
    if not over_udp:
        ping = await tcp_ping(host, port, timeout=PING_TIMEOUT_S)
        threshold = PING_THRESHOLD_OVERRIDE or ping_threshold_ms
        if PING_GATE and (ping is None or ping > threshold):
            return result

    deadline = time.monotonic() + PROXY_TIME_BUDGET_S
    handle = await start_engine(outbound, wait_s=ENGINE_START_WAIT_S)
    if handle is None:
        return result
    try:
        passed, total, first_ok_ms = await run_test_urls(
            handle.socks_port, test_urls, http_timeout_s, f"{host}:{port} [{handle.engine}]", deadline)
    finally:
        await handle.stop()

    result["tests_passed"] = passed
    result["tests_total"] = total
    # Success needs a latency: TCP ping, or the first answer through the tunnel
    # (UDP protocols, or networks where the bare TCP ping is filtered).
    result["ping_ms"] = (ping or first_ok_ms) if passed else (ping or 0)
    if passed:
        logger.info(f"✓ PASS [{handle.engine}] [{result['ping_ms']}ms] {passed}/{total} {host}:{port}")
    return result


ENGINE_MEM_MB = _env_float("ENGINE_MEM_MB", 14)      # budget per running engine
WORKER_RESERVE_MB = _env_float("WORKER_RESERVE_MB", 220)  # worker + speed/geo engines


def memory_concurrency_cap() -> int | None:
    """Concurrent checks the container's memory limit allows (None = no limit).

    Every check runs its own engine process; 50 of them plus the worker
    exceeded a 768 MB container and the kernel OOM-killed the worker in a
    loop — the node looked alive but stopped testing.
    """
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            raw = open(path).read().strip()
        except OSError:
            continue
        if raw == "max" or not raw.isdigit() or int(raw) > 1 << 50:
            return None
        limit_mb = int(raw) / 1048576
        return max(4, int((limit_mb - WORKER_RESERVE_MB) // ENGINE_MEM_MB))
    return None


def hard_timeout_s(http_timeout_s: float) -> float:
    """Upper bound for one check_proxy call, whatever happens inside."""
    return PING_TIMEOUT_S + ENGINE_START_WAIT_S + PROXY_TIME_BUDGET_S + float(http_timeout_s) + 10


async def run_proxy_checks(proxy_links: list[str], test_urls: list[dict], ping_threshold_ms: int,
                           http_timeout_s: float, concurrency: int, status: dict | None = None) -> list[dict]:
    """Check many proxies concurrently; returns one result per input link."""
    if CONCURRENT_OVERRIDE > 0:
        concurrency = CONCURRENT_OVERRIDE
    cap = memory_concurrency_cap()
    if cap is not None and concurrency > cap:
        logger.info(f"concurrency {concurrency} → {cap}: container memory limit")
        concurrency = cap
    limit = hard_timeout_s(http_timeout_s)
    status = status if status is not None else {}
    status.update(checked=0, passed=0)
    results: list[dict | None] = [None] * len(proxy_links)
    next_index = 0

    async def worker() -> None:
        # A fixed pool of workers: memory stays O(concurrency) even for a
        # 50k-link chunk (one coroutine per link used ~100+ MB).
        nonlocal next_index
        while next_index < len(proxy_links):
            i = next_index
            next_index += 1
            link = proxy_links[i]
            try:
                r = await asyncio.wait_for(check_proxy(link, test_urls, ping_threshold_ms, http_timeout_s), limit)
            except asyncio.TimeoutError:
                logger.warning(f"check exceeded {limit:.0f}s, dropped: {link[:60]}")
                r = {"raw_url": link, "ping_ms": 0, "tests_passed": 0, "tests_total": len(test_urls)}
            except Exception as e:  # a bug in one check must not kill the batch
                logger.error(f"check crashed: {type(e).__name__}: {e}")
                r = {"raw_url": link, "ping_ms": 0, "tests_passed": 0, "tests_total": len(test_urls)}
            results[i] = r
            status["checked"] += 1
            if r["tests_passed"] > 0 and r["ping_ms"] > 0:
                status["passed"] += 1

    await asyncio.gather(*(worker() for _ in range(max(1, min(concurrency, len(proxy_links))))))
    return results  # type: ignore[return-value]
