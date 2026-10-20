# VPN Checker — common tasks
set shell := ["bash", "-cu"]

# Syntax-check all Python modules (no third-party deps required)
check:
    python3 -m compileall -q main.py scheduler.py database.py subs_manager.py db_maintenance.py
    @echo "compileall OK"

# One-shot SQLite maintenance: orphan cleanup, duplicate indexes, VACUUM
db-maintenance:
    python3 db_maintenance.py

# Build and start the panel (docker compose)
up:
    docker compose up -d --build

down:
    docker compose down

logs:
    docker compose logs -f --tail=200
