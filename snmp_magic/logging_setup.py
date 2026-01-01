# snmp_magic/logging_setup.py
import logging
import sys
from typing import Optional, List, Tuple

def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """
    Configure project-wide logging.
    - level: DEBUG/INFO/WARNING/ERROR/CRITICAL
    - log_file: if provided, logs also go to this file
    Console always logs; log file is optional.
    """
    root = logging.getLogger()  # root logger
    if getattr(root, "_snmp_magic_configured", False):
        return

    # Parse level
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)

    # Console handler (human-readable)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(lvl)
    ch.setFormatter(logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    root.setLevel(lvl)
    root.handlers[:] = [ch]

    # Optional file handler
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(lvl)
        fh.setFormatter(logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        root.addHandler(fh)

    # Mark configured to avoid double init
    root._snmp_magic_configured = True

class RingBufferHandler(logging.Handler):
    """In-memory rolling log buffer for UI."""
    def __init__(self, max_lines: int = 1000):
        super().__init__()
        self.max_lines = max_lines
        self.lines: List[str] = []

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.lines.append(msg)
            if len(self.lines) > self.max_lines:
                del self.lines[:-self.max_lines]
        except Exception:
            pass

_ui_log_handler: Optional[RingBufferHandler] = None

def attach_ui_log_buffer(max_lines: int = 1000):
    """Attach in-memory buffer to the root logger so UI can read logs."""
    global _ui_log_handler
    if _ui_log_handler is not None:
        return _ui_log_handler
    root = logging.getLogger()
    h = RingBufferHandler(max_lines=max_lines)
    h.setLevel(root.level or logging.INFO)
    h.setFormatter(logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    ))
    root.addHandler(h)
    _ui_log_handler = h
    return h

def get_ui_logs_from(offset: int = 0) -> Tuple[int, List[str]]:
    """Return (next_offset, lines[offset:]) for polling."""
    buf = _ui_log_handler.lines if _ui_log_handler else []
    if offset < 0: offset = 0
    if offset > len(buf): offset = len(buf)
    return len(buf), buf[offset:]