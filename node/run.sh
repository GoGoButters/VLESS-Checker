#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PATH="${SCRIPT_DIR}/.venv"
ENV_FILE="${SCRIPT_DIR}/.env"

if [ ! -d "${VENV_PATH}" ]; then
    echo "ERROR: Virtual environment not found. Run setup.sh first."
    exit 1
fi

if [ -f "${ENV_FILE}" ]; then
    echo "Loading config from ${ENV_FILE}..."
    set -a
    source "${ENV_FILE}"
    set +a
fi

source "${VENV_PATH}/bin/activate"

cd "${PROJECT_ROOT}/node"

export PYTHONUNBUFFERED=1
export SINGBOX_PATH="${SINGBOX_PATH:-/usr/local/bin/sing-box}"

echo "=== Starting VPN Checker Worker Node ==="
echo "Master URL: ${MASTER_URL:-http://127.0.0.1:8000}"
echo "Node Name: ${NODE_NAME:-standalone-worker}"
echo "Node Region: ${NODE_REGION:-unknown}"
echo "sing-box path: ${SINGBOX_PATH}"
echo ""

python3 main.py