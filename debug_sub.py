from sqlmodel import Session, select, delete
from database import engine, Subscription, RawProxy
import asyncio
from subs_manager import fetch_and_parse_subscriptions

def add_sub():
    with Session(engine) as session:
        session.exec(delete(Subscription))
        url = "https://n8n2.dedyn.io/webhook/c0422f11-e4cf-4cc4-8087-00ef0d7635ad?tg_id=35145416&username=dedynio&secret=050970bcd3c5fc5a387aa07c1d241bba"
        session.add(Subscription(url=url))
        session.commit()
        print("Subscription added successfully!")

async def fetch_now():
    proxy_links = await fetch_and_parse_subscriptions()
    with Session(engine) as session:
        session.exec(delete(RawProxy))
        for url in proxy_links:
            session.add(RawProxy(raw_url=url))
        session.commit()
    print(f"Fetched {len(proxy_links)} proxies and stored in DB.")

if __name__ == "__main__":
    add_sub()
    asyncio.run(fetch_now())
