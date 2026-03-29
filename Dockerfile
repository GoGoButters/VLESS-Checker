FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install sing-box
ARG SB_VERSION=1.11.4
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) SB_ARCH="amd64" ;; \
      arm64) SB_ARCH="armv8" ;; \
      armhf) SB_ARCH="armv7" ;; \
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    wget -q "https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${SB_ARCH}.tar.gz" -O /tmp/sb.tar.gz && \
    tar -xzf /tmp/sb.tar.gz -C /tmp/ && \
    mv /tmp/sing-box-${SB_VERSION}-linux-${SB_ARCH}/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*

# Verify sing-box is working
RUN sing-box version

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for SQLite DB
RUN mkdir -p /app/data

# Set environment
ENV SINGBOX_PATH=/usr/local/bin/sing-box
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
