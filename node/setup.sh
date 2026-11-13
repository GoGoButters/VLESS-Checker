#!/bin/bash
# Standalone (non-Docker) worker setup: sing-box + Xray-core + Python venv.
set -euo pipefail

SINGBOX_VERSION="1.14.4"
XRAY_VERSION="26.11.9"
BIN_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

case "$(uname -m)" in
    x86_64) SB_ARCH=amd64; XR_ARCH=64 ;;
    aarch64) SB_ARCH=arm64; XR_ARCH=arm64-v8a ;;
    armv7l) SB_ARCH=armv7; XR_ARCH=arm32-v7a ;;
    *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

echo "[1/4] System packages"
if command -v apt-get >/dev/null; then
    apt-get update && apt-get install -y --no-install-recommends python3 python3-venv wget unzip ca-certificates
elif command -v dnf >/dev/null; then
    dnf install -y python3 wget unzip ca-certificates
elif command -v apk >/dev/null; then
    apk add --no-cache python3 py3-pip wget unzip ca-certificates
else
    echo "Install python3 (3.11+), wget, unzip manually"; exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[2/4] sing-box ${SINGBOX_VERSION}"
wget -qO "$TMP/sb.tgz" "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}.tar.gz"
tar -xzf "$TMP/sb.tgz" -C "$TMP"
install -m 755 "$TMP/sing-box-${SINGBOX_VERSION}-linux-${SB_ARCH}/sing-box" "$BIN_DIR/sing-box"

echo "[3/4] Xray-core ${XRAY_VERSION}"
wget -qO "$TMP/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XR_ARCH}.zip"
unzip -q -o "$TMP/xray.zip" xray -d "$TMP"
install -m 755 "$TMP/xray" "$BIN_DIR/xray"

echo "[4/4] Python environment"
python3 -m venv "$SCRIPT_DIR/.venv"
"$SCRIPT_DIR/.venv/bin/pip" install -q --upgrade pip
"$SCRIPT_DIR/.venv/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"

sing-box version | head -1
xray version | head -1
echo
echo "Done. Configure: cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env && nano $SCRIPT_DIR/.env"
echo "Run:       $SCRIPT_DIR/run.sh"
