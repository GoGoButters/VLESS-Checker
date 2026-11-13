FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data

# Fewer glibc malloc arenas: far less fragmentation in a threaded server
ENV PYTHONUNBUFFERED=1 MALLOC_ARENA_MAX=2
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
