"""Subscription manager: fetches, parses, and deduplicates VLESS links."""

import base64
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor

import httpx
from datetime import datetime, timezone
from sqlmodel import Session, select


from database import Subscription, RawProxy, Settings, engine
from database import NodeProxyResult, SubscriptionTestStat  # [SUB-STATS]

logger = logging.getLogger("vpn_checker.subs_manager")

# Per-request HTTP budget. Some mirrors (e.g. gitverse.ru) regularly stall for
# 20-32s; fail fast so one slow mirror cannot stretch the whole fetch cycle.
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
# [SUB-STATS] сколько последних выборок на источник держим в БД (страница берёт 5)
SUB_STATS_KEEP = 10
# [SUB-AUTOSKIP] окно «нулевой живости»: сколько последних выборок смотрим
SUB_STATS_WINDOW = 5
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


def _set_signature(links: list[str]) -> str:
    """[SUB-AUTOSKIP] Подпись набора конфигов источника.

    Идентичность конфига — ссылка без #remark (как в дедупликации), поэтому смена
    порядка строк и правка подписи в #name подпись не меняют. Пусто -> "".
    """
    ids = sorted({_strip_remark(u) for u in links if u})
    if not ids:
        return ""
    return hashlib.sha1("\n".join(ids).encode("utf-8")).hexdigest()


def _zero_live_window(samples: list[tuple[int, int]], window: int = SUB_STATS_WINDOW) -> bool:
    """[SUB-AUTOSKIP] True, если за последние window выборок не было ни одного живого.

    samples — [(tested, alive), ...] в порядке «свежие сверху».
    """
    if len(samples) < window:
        return False
    return sum(alive for _tested, alive in samples[:window]) == 0


def _decide_source(sub, samples: list[tuple[int, int]], signature: str,
                   window: int = SUB_STATS_WINDOW) -> str:
    """[SUB-AUTOSKIP] Что делать с источником в этом цикле.

    "skip"      — уже отключён и набор конфигов не изменился: не тестируем;
    "reenable"  — был отключён, но набор изменился: включаем и тестируем;
    "disable"   — 0 живых за window прогонов: отключаем тесты;
    "test"      — обычные основания.
    """
    if sub.stats_disabled:
        if signature and signature == (sub.disabled_signature or ""):
            return "skip"
        return "reenable"
    if _zero_live_window(samples, window):
        return "disable"
    return "test"


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

    # [SUB-AUTOSKIP] последние выборки по источникам (свежие сверху) — решаем по ним
    stats_by_sub: dict[int, list[tuple[int, int]]] = {}
    if session is not None:
        with Session(engine) as st_read:
            for row in st_read.exec(
                select(SubscriptionTestStat).order_by(SubscriptionTestStat.id.desc())
            ).all():
                bucket = stats_by_sub.setdefault(row.subscription_id, [])
                if len(bucket) < SUB_STATS_KEEP:
                    bucket.append((row.tested, row.alive))

    # [SUB-STATS] какие конфиги сейчас считаются живыми (успели пройти тесты)
    sub_by_url = {sub.url: sub for sub in active_subs}
    sub_id_by_url = {sub.url: sub.id for sub in active_subs}
    good_ids: set[str] = set()
    if session is not None:
        with Session(engine) as res_session:
            for row in res_session.exec(
                select(NodeProxyResult.raw_url)
                .where(NodeProxyResult.tests_passed > 0)
                .distinct()
            ).all():
                url = row[0] if isinstance(row, tuple) else row
                if url:
                    good_ids.add(str(url).split("#", 1)[0])
    stat_rows: list[tuple[int, int, int]] = []

    for sub_url, proxy_links in fetched:
        # [SUB-AUTOSKIP] решаем судьбу источника до фильтрации
        sub = sub_by_url.get(sub_url)
        if session is not None and sub is not None:
            signature = _set_signature(proxy_links)
            decision = _decide_source(sub, stats_by_sub.get(sub.id, []), signature)
            if decision == "skip":
                logger.info(
                    f"[SUB-AUTOSKIP] {sub_url}: 0 живых за {SUB_STATS_WINDOW} прогонов и набор не менялся "
                    f"({len(proxy_links)} конфигов) — прокси не тестируем, источник опрашиваем дальше"
                )
                sub_proxy_counts[sub_url] = len(proxy_links)
                continue
            if decision == "reenable":
                sub.stats_disabled = False
                sub.disabled_signature = ""
                sub.disabled_at = ""
                stats_by_sub[sub.id] = []
                session.add(sub)
                with Session(engine) as clean_st:
                    for row in clean_st.exec(
                        select(SubscriptionTestStat).where(SubscriptionTestStat.subscription_id == sub.id)
                    ).all():
                        clean_st.delete(row)
                    clean_st.commit()
                logger.info(f"[SUB-AUTOSKIP] {sub_url}: набор конфигов изменился — источник возвращён в тесты")
            elif decision == "disable":
                sub.stats_disabled = True
                sub.disabled_signature = signature
                sub.disabled_at = datetime.now(timezone.utc).isoformat()
                session.add(sub)
                logger.info(
                    f"[SUB-AUTOSKIP] {sub_url}: 0 живых за {SUB_STATS_WINDOW} прогонов — тесты отключены "
                    f"({len(proxy_links)} конфигов), набор запомнен для сравнения"
                )
                sub_proxy_counts[sub_url] = len(proxy_links)
                continue

        if proxy_links:
            # Filter out banned proxies
            filtered = [url for url in proxy_links if url not in banned_urls]
            if len(filtered) < len(proxy_links):
                logger.info(f"Filtered out {len(proxy_links) - len(filtered)} banned proxies from {sub_url}")
            all_proxies.extend(filtered)
            sub_proxy_counts[sub_url] = len(filtered)
            # [SUB-STATS] уникальные конфиги источника и сколько из них живо
            if session is not None:
                ids = {url.split("#", 1)[0] for url in filtered}
                sub_id = sub_id_by_url.get(sub_url)
                if sub_id is not None:
                    stat_rows.append((sub_id, len(ids), len(ids & good_ids)))
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

    # [SUB-STATS] пишем выборку за цикл; на источник держим только SUB_STATS_KEEP последних
    if session is not None and stat_rows:
        import database as _db
        gen = str(getattr(_db, "generation_id", "") or "")
        now_iso = datetime.now(timezone.utc).isoformat()
        with Session(engine) as st:
            for sub_id, tested, alive in stat_rows:
                st.add(SubscriptionTestStat(
                    subscription_id=sub_id, generation_id=gen,
                    checked_at=now_iso, tested=tested, alive=alive,
                ))
            st.commit()
            for sub_id, _tested, _alive in stat_rows:
                rows_old = st.exec(
                    select(SubscriptionTestStat)
                    .where(SubscriptionTestStat.subscription_id == sub_id)
                    .order_by(SubscriptionTestStat.id.desc())
                ).all()
                for row in rows_old[SUB_STATS_KEEP:]:
                    st.delete(row)
            st.commit()
        logger.info(f"[SUB-STATS] записано выборок: {len(stat_rows)}")

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
