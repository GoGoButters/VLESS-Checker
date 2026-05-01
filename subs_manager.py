"""Subscription manager: fetches, parses, and deduplicates VLESS links."""

import base64
import logging
import httpx
from datetime import datetime, timezone, timedelta
from sqlmodel import Session, select


from database import Subscription, RawProxy, Settings, engine

logger = logging.getLogger("vpn_checker.subs_manager")


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


def _extract_proxy_links(text: str) -> list[str]:
    """Extract all supported proxy links from text."""
    links = []
    protocols = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://")
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith(protocols):
            links.append(line)
    return links


async def fetch_and_parse_subscriptions(session=None) -> list[str]:
    """Fetch all subscription URLs and extract unique VLESS link.
    If session is provided, updates last_config_count for each subscription.
    Only fetches from enabled subscriptions if session is provided.

    Excludes proxies that are currently banned (banned_until > now).
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
    
    all_proxies: list[str] = []
    sub_proxy_counts = {}  # Track proxy count per subscription

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        for sub in subs:
            # Skip disabled subscriptions if we have a session (meaning we're in the full fetch flow)
            if session is not None and not sub.is_enabled:
                logger.info(f"Skipping disabled subscription: {sub.url}")
                continue
            
            try:
                logger.info(f"Fetching subscription: {sub.url}")
                resp = await client.get(sub.url)
                resp.raise_for_status()
                raw_text = resp.text.strip()
                
                # Try base64 decode first
                decoded = _decode_base64(raw_text)
                proxy_links = _extract_proxy_links(decoded)
                
                # If no links found via base64, try raw text
                if not proxy_links:
                    proxy_links = _extract_proxy_links(raw_text)
                
                if proxy_links:
                    # Filter out banned proxies
                    filtered = [url for url in proxy_links if url not in banned_urls]
                    if len(filtered) < len(proxy_links):
                        logger.info(f"Filtered out {len(proxy_links) - len(filtered)} banned proxies from {sub.url}")
                    all_proxies.extend(filtered)
                    sub_proxy_counts[sub.url] = len(filtered)
                    logger.info(f"Found {len(filtered)} proxy links in {sub.url}")
                else:
                    sub_proxy_counts[sub.url] = 0
                
            except Exception as e:
                logger.warning(f"Failed to fetch {sub.url}: {e}")
                sub_proxy_counts[sub.url] = 0

    # Update last_config_count if session is provided
    if session is not None:
        for sub in subs:
            if sub.url in sub_proxy_counts:
                sub.last_config_count = sub_proxy_counts[sub.url]
        session.add_all(subs)
        session.commit()

    # Deduplicate
    unique = list(dict.fromkeys(all_proxies))
    logger.info(f"Total unique proxy links: {len(unique)}")
    return unique
