"""Subscription manager: fetches, parses, and deduplicates VLESS links."""

import base64
import logging
from urllib.parse import unquote

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


def _extract_vless_links(text: str) -> list[str]:
    """Extract all vless:// links from text."""
    links = []
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("vless://"):
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
                vless_links = _extract_vless_links(decoded)

                # If no links found via base64, try raw text
                if not vless_links:
                    vless_links = _extract_vless_links(raw_text)

                logger.info(f"Found {len(vless_links)} VLESS links from {sub.url}")
                all_vless.extend(vless_links)

            except Exception as e:
                logger.warning(f"Failed to fetch {sub.url}: {e}")

    # Deduplicate
    unique = list(dict.fromkeys(all_vless))
    logger.info(f"Total unique VLESS links: {len(unique)}")
    return unique
