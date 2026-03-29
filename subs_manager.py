"""Subscription manager: fetches, parses, and deduplicates VLESS links."""

import base64
import logging
from urllib.parse import urlparse

import httpx
from sqlmodel import Session, select

from database import Subscription, engine

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


async def fetch_and_parse_subscriptions() -> list[str]:
    """Fetch all subscription URLs and extract unique VLESS links."""
    with Session(engine) as session:
        subs = session.exec(select(Subscription)).all()

    all_vless: list[str] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(15.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        for sub in subs:
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
                    all_vless.extend(proxy_links)
                    logger.info(f"Found {len(proxy_links)} proxy links in {sub.url}")

            except Exception as e:
                logger.warning(f"Failed to fetch {sub.url}: {e}")

    # Deduplicate
    unique = list(dict.fromkeys(all_vless))
    logger.info(f"Total unique VLESS links: {len(unique)}")
    return unique
