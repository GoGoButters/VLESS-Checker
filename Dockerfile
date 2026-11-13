FROM python:3.11-slim

ARG XRAY_VERSION="26.3.27"

# Set working directory
WORKDIR /app

# Xray-core: проверка транспортов, которых нет в sing-box (xhttp/splithttp)
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && wget -qO /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
    && unzip -o -q /tmp/xray.zip -d /tmp/xray \
    && mv /tmp/xray/xray /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm -rf /tmp/xray*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for SQLite DB
RUN mkdir -p /app/data

# Set environment
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
