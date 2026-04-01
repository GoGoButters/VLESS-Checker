"""In-memory ring buffer log handler for real-time log viewing."""

import logging
import threading
from collections import deque
from datetime import datetime, timezone


class LogBuffer:
    """Thread-safe ring buffer for log records."""

    def __init__(self, maxlen: int = 1000):
        self._buffer: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._counter = 0

    def append(self, record: dict):
        with self._lock:
            self._counter += 1
            record["id"] = self._counter
            self._buffer.append(record)

    def get_all(self) -> list[dict]:
        with self._lock:
            return list(self._buffer)

    def get_since(self, after_id: int) -> list[dict]:
        with self._lock:
            return [r for r in self._buffer if r["id"] > after_id]

    def clear(self):
        with self._lock:
            self._buffer.clear()
            self._counter = 0


class BufferHandler(logging.Handler):
    """Custom logging handler that writes to a LogBuffer."""

    def __init__(self, buffer: LogBuffer):
        super().__init__()
        self.log_buffer = buffer

    def emit(self, record: logging.LogRecord):
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": self.format(record),
            }
            self.log_buffer.append(entry)
        except Exception:
            pass


# Global singleton
log_buffer = LogBuffer(maxlen=1000)


def setup_log_buffer():
    """Attach the buffer handler to the root logger."""
    handler = BufferHandler(log_buffer)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)
    # Also capture uvicorn logs
    for logger_name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        logging.getLogger(logger_name).addHandler(handler)
