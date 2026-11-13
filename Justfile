# VPN Checker — common tasks
set shell := ["bash", "-cu"]

# Syntax-check all Python modules
check:
    python3 -m compileall -q *.py node/*.py tests/*.py
    @echo "compileall OK"

# Test suite (engine tests need SINGBOX_PATH / XRAY_PATH and openssl)
test:
    python3 -m pytest -q -p no:cacheprovider tests/

# One-shot SQLite maintenance (VACUUM when worthwhile, optimize, WAL checkpoint)
db-maintenance:
    python3 db_maintenance.py

# Build and start the panel
up:
    docker compose up -d --build

down:
    docker compose down

logs:
    docker compose logs -f --tail=200
