from sqlmodel import Session, select
from database import engine, Settings

with Session(engine) as session:
    settings = session.exec(select(Settings)).first()
    if settings:
        print(f"TOKEN={settings.node_api_token}")
    else:
        print("No settings found")
