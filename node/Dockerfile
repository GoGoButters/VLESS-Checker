FROM python:3.11-slim

ARG SINGBOX_VERSION="1.11.4"
ARG ARCH="amd64"

# Install basics and download sing-box
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz" \
    && tar -xzf /tmp/sing-box.tar.gz -C /tmp/ \
    && mv /tmp/sing-box-${SINGBOX_VERSION}-linux-${ARCH}/sing-box /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf /tmp/sing-box*

WORKDIR /app

# Copy and install root requirements (shared deps like httpx, proxy_parsers etc.)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy and install node-specific requirements (pydantic-settings etc.)
COPY node/requirements.txt /app/node-requirements.txt
RUN pip install --no-cache-dir -r /app/node-requirements.txt

# Copy all parent files since we share proxy_parsers and tester logic
COPY . /app/

# Workdir for node
WORKDIR /app/node

ENV PYTHONUNBUFFERED=1
ENV SINGBOX_PATH=/usr/local/bin/sing-box

CMD ["python", "main.py"]
