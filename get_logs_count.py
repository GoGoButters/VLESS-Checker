from sqlmodel import Session, select, func
from database import engine, NodeLog

with Session(engine) as session:
    count = session.exec(select(func.count(NodeLog.id))).one()
    print(f"Log count: {count}")
    
    last_log = session.exec(select(NodeLog).order_by(NodeLog.timestamp.desc()).limit(1)).first()
    if last_log:
        print(f"Last log: {last_log.timestamp} - {last_log.node_name} - {last_log.message}")
