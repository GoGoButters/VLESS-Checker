#!/bin/bash
set -e

SINGBOX_VERSION="1.11.4"
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
elif [ "$ARCH" = "armv7l" ]; then
    ARCH="armv7"
fi

echo "=== VPN Checker Worker Node - Standalone Setup ==="
echo "Architecture detected: $ARCH"

echo ""
echo "[1/4] Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv curl wget ca-certificates \
        libmagic1 file
elif command -v dnf &> /dev/null; then
    dnf install -y python3 python3-pip curl wget ca-certificates file-devel
elif command -v apk &> /dev/null; then
    apk add --no-cache python3 py3-pip curl wget ca-certificates file
else
    echo "ERROR: Unsupported package manager. Please install manually:"
    echo "  - Python 3.11+"
    echo "  - pip"
    echo "  - curl, wget"
    exit 1
fi

echo ""
echo "[2/4] Downloading and installing sing-box v${SINGBOX_VERSION}..."
SINGBOX_DIR="/usr/local/bin"
if [ -f "${SINGBOX_DIR}/sing-box" ]; then
    echo "  sing-box already installed at ${SINGBOX_DIR}/sing-box"
    CURRENT_VER=$(${SINGBOX_DIR}/sing-box version 2>/dev/null | head -1 || echo "unknown")
    echo "  Current version: ${CURRENT_VER}"
else
    TEMP_DIR=$(mktemp -d)
    cd "${TEMP_DIR}"
    wget -q "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz" -O sing-box.tar.gz
    tar -xzf sing-box.tar.gz
    mv "sing-box-${SINGBOX_VERSION}-linux-${ARCH}/sing-box" "${SINGBOX_DIR}/"
    chmod +x "${SINGBOX_DIR}/sing-box"
    rm -rf "${TEMP_DIR}"
    echo "  Installed sing-box v${SINGBOX_VERSION} to ${SINGBOX_DIR}/sing-box"
fi

echo ""
echo "[3/4] Setting up Python virtual environment..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PATH="${SCRIPT_DIR}/.venv"

if [ ! -d "${VENV_PATH}" ]; then
    python3 -m venv "${VENV_PATH}"
fi

source "${VENV_PATH}/bin/activate"

pip install --upgrade pip wheel setuptools 2>/dev/null || pip install --upgrade pip
pip install httpx pydantic-settings pydantic

echo "  Python packages installed: httpx, pydantic-settings, pydantic"
deactivate

echo ""
echo "[4/4] Verifying installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

if ! command -v sing-box &> /dev/null; then
    echo "ERROR: sing-box not found"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
echo "  Python version: ${PYTHON_VERSION}"
echo "  sing-box: $(sing-box version | head -1)"

echo ""
echo "=== Setup complete! ==="
echo ""
echo "To start the worker, run:"
echo "  cd ${PROJECT_ROOT}/node"
echo "  source .venv/bin/activate"
echo "  MASTER_URL=http://<MASTER_IP>:8000 NODE_TOKEN=<TOKEN> python3 main.py"
echo ""
echo "Or use the provided run.sh script:"
echo "  ./run.sh"
echo ""