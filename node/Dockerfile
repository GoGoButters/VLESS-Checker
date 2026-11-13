FROM python:3.11-slim

# sing-box checks most proxies; Xray-core checks what only it supports
# (xhttp/splithttp, mKCP, HTTP-header obfuscation, VLESS encryption).
ARG SINGBOX_VERSION="1.14.4"
ARG XRAY_VERSION="26.11.9"
ARG TARGETARCH

RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends ca-certificates wget unzip; \
    rm -rf /var/lib/apt/lists/*; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64) sb=amd64; xr=64 ;; \
        arm64) sb=arm64; xr=arm64-v8a ;; \
        armhf|arm) sb=armv7; xr=arm32-v7a ;; \
        *) echo "unsupported architecture: $arch"; exit 1 ;; \
    esac; \
    wget -qO /tmp/sb.tgz "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${sb}.tar.gz"; \
    tar -xzf /tmp/sb.tgz -C /tmp; \
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${sb}/sing-box" /usr/local/bin/; \
    wget -qO /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${xr}.zip"; \
    unzip -q /tmp/xray.zip xray -d /usr/local/bin; \
    chmod +x /usr/local/bin/sing-box /usr/local/bin/xray; \
    rm -rf /tmp/*; \
    apt-get purge -y wget unzip; apt-get autoremove -y; \
    sing-box version; xray version

WORKDIR /app
COPY node/requirements.txt /app/node/requirements.txt
RUN pip install --no-cache-dir -r /app/node/requirements.txt

# Only the checker modules the worker needs (no panel code)
COPY tester.py engine_driver.py proxy_parsers.py speed_tester.py geo_checker.py /app/
COPY node/main.py node/config.py /app/node/

WORKDIR /app/node
ENV PYTHONUNBUFFERED=1 \
    MALLOC_ARENA_MAX=2 \
    SINGBOX_PATH=/usr/local/bin/sing-box \
    XRAY_PATH=/usr/local/bin/xray

CMD ["python", "main.py"]
