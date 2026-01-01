# snmp_magic/probe.py
from __future__ import annotations
import json, os, time
from typing import Any, Dict

# Enable by setting PROBE_OUT (e.g., "./probes/vendor_probe.ndjson")
PROBE_OUT = os.getenv("PROBE_OUT", "").strip()  # empty => disabled
# 'miss' (default) -> only when something is missing; 'always' -> log every probe call
PROBE_MODE = (os.getenv("PROBE_MODE", "miss") or "miss").lower()

def _should_log(event: Dict[str, Any]) -> bool:
    if not PROBE_OUT:
        return False
    if PROBE_MODE == "always":
        return True
    # Default: only log "miss" or "fallback" or explicit failure outcomes
    outcome = str(event.get("outcome") or event.get("decision") or "").lower()
    return outcome in {"miss", "empty", "fallback", "skipped", "notfound", "novlan", "nopvid"}

def probe_log(event: Dict[str, Any]) -> None:
    """
    Append a compact JSON line to PROBE_OUT when enabled.
    Does nothing if PROBE_OUT is unset or _should_log() is False.
    """
    if not PROBE_OUT:
        return
    try:
        if "ts" not in event:
            # ISO-ish timestamp, UTC
            event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if _should_log(event):
            os.makedirs(os.path.dirname(PROBE_OUT), exist_ok=True)
            with open(PROBE_OUT, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        # Never break scans because of logging
        pass
