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
    """Attach the buffer handler to the root logger and uvicorn's own logger.

    Access logs stay out: heartbeats and polls would push every useful line
    out of the 1000-entry buffer within minutes.
    """
    root = logging.getLogger()
    if any(isinstance(h, BufferHandler) for h in root.handlers):
        return
    handler = BufferHandler(log_buffer)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
    root.addHandler(handler)
    logging.getLogger("uvicorn").addHandler(handler)
    logging.getLogger("httpx").setLevel(logging.WARNING)
