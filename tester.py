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
from proxy_parsers import parse_proxy_url
from engine_driver import start_engine, needs_xray, engine_for

logger = logging.getLogger("vpn_checker.tester")

SINGBOX_PATH = os.environ.get("SINGBOX_PATH", "/usr/local/bin/sing-box")
XRAY_PATH = os.environ.get("XRAY_PATH", "/usr/local/bin/xray")

# --- Настройки проверки (переопределяются переменными окружения) -----------
# TCP_PING_GATE=0 — не отбрасывать прокси по TCP-пингу (для сетей, где
#   TCP-рукопожатие к серверу нестабильно; решает тест через туннель).
PING_GATE = os.environ.get("TCP_PING_GATE", "1").lower() not in ("0", "false", "no", "off")
PING_TIMEOUT_S = float(os.environ.get("TCP_PING_TIMEOUT_S", "3"))
PING_THRESHOLD_OVERRIDE = int(os.environ.get("PING_THRESHOLD_MS_OVERRIDE", "0") or 0)
ENGINE_START_WAIT_S = float(os.environ.get("ENGINE_START_WAIT_S", "4"))
TEST_URL_RETRIES = max(1, int(os.environ.get("TEST_URL_RETRIES", "2")))
MAX_CONSECUTIVE_FAILURES = max(1, int(os.environ.get("MAX_CONSECUTIVE_FAILURES", "3")))
# Общий бюджет времени на один прокси: прокси, у которого туннель «висит»
# (соединение есть, данных нет), не должен съедать все таймауты всех URL.
PROXY_TIME_BUDGET_S = float(os.environ.get("PROXY_TIME_BUDGET_S", "30"))

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
    bind_interface = os.environ.get("BIND_INTERFACE", "")
    if bind_interface:
        outbound["bind_interface"] = bind_interface
    return {
        "log": {
            "disabled": False,
            "level": "debug"
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }
        ],
        "outbounds": [
            outbound
        ],
    }


async def _run_test_urls(socks_port: int, test_urls: list[dict], http_timeout_s: int,
                         label: str = "", deadline: float | None = None) -> tuple[int, int]:
    """Прогон тестовых URL через локальный SOCKS. Возвращает (passed, total).

    Каждый URL пробуется TEST_URL_RETRIES раз: у только что поднятого туннеля
    первый запрос часто отваливается («холодный старт»). После
    MAX_CONSECUTIVE_FAILURES неудач подряд прогон прекращается, чтобы мёртвый
    прокси не тратил все таймауты.
    """
    local_proxy_url = f"socks5://127.0.0.1:{socks_port}"
    total = len(test_urls)
    passed = 0
    consecutive_failures = 0

    for tu in test_urls:
        if deadline is not None and time.monotonic() >= deadline:
            logger.info(f"{label}: бюджет времени {PROXY_TIME_BUDGET_S:.0f}с исчерпан, останавливаю прогон URL")
            break
        ok = False
        last_error = ""
        # не даём одному запросу выйти за общий бюджет прокси
        req_timeout = float(http_timeout_s)
        if deadline is not None:
            req_timeout = max(3.0, min(req_timeout, deadline - time.monotonic()))
        for _attempt in range(TEST_URL_RETRIES):
            try:
                use_verify = not tu["url"].endswith("/generate_204")
                async with httpx.AsyncClient(
                    proxy=local_proxy_url,
                    timeout=httpx.Timeout(req_timeout),
                    verify=use_verify,
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(tu["url"])
                    body_len = len(resp.content)
                    if resp.status_code == tu["expect_status"] and body_len >= tu["min_body_bytes"]:
                        ok = True
                        break
                    last_error = (f"status={resp.status_code} (ждём {tu['expect_status']}), "
                                  f"body={body_len}b (мин {tu['min_body_bytes']}b)")
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"

        if ok:
            passed += 1
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            logger.warning(f"Test URL {tu['url']} не прошёл для {label}: {last_error}")
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                logger.info(f"{label}: прогон URL прерван после {consecutive_failures} неудач подряд")
                break

    return passed, total


async def _check_one(proxy_url: str, semaphore: asyncio.Semaphore, ping_threshold: int,
                     http_timeout_s: int, test_urls: list[dict], status_ref: dict) -> tuple | None:
    """Проверка одного прокси: TCP-пинг → поднятие туннеля → тестовые URL."""
    async with semaphore:
        try:
            parsed_outbound = parse_proxy_url(proxy_url)
        except Exception:
            parsed_outbound = None
        if not parsed_outbound:
            status_ref["checked"] += 1
            status_ref["failed"] += 1
            return None

        host = parsed_outbound.get("server", "")
        port = int(parsed_outbound.get("server_port", 443))

        ping = await _tcp_ping(host, port, timeout=PING_TIMEOUT_S)
        threshold = PING_THRESHOLD_OVERRIDE or ping_threshold
        if PING_GATE and (ping is None or ping > threshold):
            status_ref["checked"] += 1
            status_ref["failed"] += 1
            return None

        deadline = time.monotonic() + PROXY_TIME_BUDGET_S
        socks_port = _get_free_port()
        handle = await start_engine(parsed_outbound, socks_port, wait_s=ENGINE_START_WAIT_S)
        if handle is None:
            status_ref["checked"] += 1
            status_ref["failed"] += 1
            return None

        try:
            tests_passed, tests_total = await _run_test_urls(
                socks_port, test_urls, http_timeout_s,
                label=f"{host}:{port} [{handle.engine}]", deadline=deadline
            )
        finally:
            await handle.stop()

        if tests_passed > 0:
            status_ref["checked"] += 1
            status_ref["passed"] += 1
            logger.info(f"✓ PASS [{handle.engine}] [{ping}ms] {tests_passed}/{tests_total} {host}:{port}")
            return (proxy_url, ping or 0, tests_passed, tests_total)

        status_ref["checked"] += 1
        status_ref["failed"] += 1
        return None


async def _check_single_proxy(proxy_url: str, semaphore: asyncio.Semaphore, ping_threshold: int,
                              http_timeout_s: int, test_urls: list[dict]) -> tuple | None:
    """Совместимость со старым API (мастерская проверка одиночного прокси)."""
    return await _check_one(proxy_url, semaphore, ping_threshold, http_timeout_s, test_urls, test_status)


async def _check_single_proxy_internal(proxy_url: str, semaphore: asyncio.Semaphore, ping_threshold: int,
                                       http_timeout_s: int, test_urls: list[dict],
                                       status_ref: dict, singbox_path: str = "") -> tuple | None:
    """Совместимость со старым API (проверка на удалённой ноде)."""
    return await _check_one(proxy_url, semaphore, ping_threshold, http_timeout_s, test_urls, status_ref)


async def run_proxy_checks(
    proxy_links: list[str],
    test_urls: list[dict],
    ping_threshold: int,
    http_timeout_s: int,
    concurrent_limit: int,
    status_dict: dict,
    singbox_path: str = SINGBOX_PATH,
    port_start: int = 0  # Compatibility with old signature
) -> list[ProxyResult]:
    """
    Core testing loop used by both master and remote nodes.
    Returns a list of ProxyResult objects.

    Движок выбирается по каждому прокси: sing-box или Xray-core
    (xhttp/splithttp умеет только Xray) — см. engine_driver.
    """
    override = int(os.environ.get("CONCURRENT_CHECKS_OVERRIDE", "0") or 0)
    if override > 0:
        concurrent_limit = override

    semaphore = asyncio.Semaphore(concurrent_limit)
    tasks = [
        _check_one(link, semaphore, ping_threshold, http_timeout_s, test_urls, status_dict)
        for link in proxy_links
    ]
    results = await asyncio.gather(*tasks)

    valid = []
    now = datetime.now(timezone.utc).isoformat()
    for r in results:
        if r:
            p_url, ping_ms, passed, total = r
            valid.append(ProxyResult(
                raw_url=p_url,
                ping_ms=ping_ms,
                tests_passed=passed,
                tests_total=total,
                tested_at=now
            ))
    return valid


async def run_full_test(proxy_links: list[str]) -> list[ProxyResult]:
    """Run the full test pipeline on a list of proxy links (Master)."""
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

    proxy_links = list(dict.fromkeys(proxy_links))
    test_status["running"] = True
    test_status["total"] = len(proxy_links)
    test_status["checked"] = 0
    test_status["passed"] = 0
    test_status["failed"] = 0
    test_status["current_phase"] = "checking"

    logger.info(f"Master starting test on {len(proxy_links)} proxies...")

    valid = await run_proxy_checks(
        proxy_links, test_urls, ping_threshold, http_timeout_s, concurrent_limit, test_status
    )

    # Sort: most tests passed first, then lowest ping
    valid.sort(key=lambda x: (-x.tests_passed, x.ping_ms))

    # Save to DB
    test_status["current_phase"] = "saving"
    with Session(engine) as session:
        from sqlmodel import delete
        session.exec(delete(ProxyResult))
        for p in valid:
            session.add(p)
        session.commit()

    # Optional: Speed test phase (Master)
    from speed_tester import run_speed_test
    await run_speed_test(test_status)

    test_status["current_phase"] = "tested"
    test_status["running"] = False
    logger.info(f"Test complete: {len(valid)} passed out of {len(proxy_links)}")

    return valid
