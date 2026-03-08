# snmp_magic/discovery.py
"""
Network discovery: ping sweep + SNMP probe over a CIDR block.

Key fixes vs previous version:
- Single ping_host implementation (cross-platform, with UDP fallback)
- snmp_check creates transport once per host (not twice)
- discover_cidr uses as_completed so fast hosts return immediately
- discover_cidr accepts a progress callback for real-time UI updates
- No duplicate HostProbe / helpers scattered across files
"""

import sys
import socket
import subprocess
import platform
import logging
from ipaddress import ip_network
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .snmpio import transport, snmp_get
from .mibs import OID
from .store import save_scan

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class HostProbe:
    ip: str
    ping_ok: bool
    snmp_ok: bool
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None


# ---------------------------------------------------------------------------
# Ping  (one authoritative implementation)
# ---------------------------------------------------------------------------

def ping_host(host: str, timeout_ms: int = 800) -> bool:
    """
    Returns True if host responds to ping within timeout_ms.

    Strategy:
      1. System ping subprocess (most reliable, works through firewalls that
         block TCP but allow ICMP).
      2. UDP connect() fallback — not a real ping, but catches hosts that
         block ICMP while running SNMP on 161.

    Platform notes:
      - Windows : -n 1  -w <ms>
      - macOS   : -c 1  -W <ms>   (macOS -W is already milliseconds)
      - Linux   : -c 1  -W <sec>  (Linux -W is seconds, minimum 1)
    """
    system = platform.system().lower()

    try:
        if system.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), host]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_ms)), host]
        else:
            # Linux: -W takes seconds, minimum 1
            sec = max(1, round(timeout_ms / 1000))
            cmd = ["ping", "-c", "1", "-W", str(sec), host]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 2,   # hard process timeout
        )
        if result.returncode == 0:
            return True

    except FileNotFoundError:
        log.debug("ping binary not found, falling back to UDP probe for %s", host)
    except subprocess.TimeoutExpired:
        pass
    except Exception as exc:
        log.debug("ping subprocess error for %s: %s", host, exc)

    # Fallback: TCP connect to common ports (22, 80, 443, 8080).
    # UDP connect() is not reliable on LANs — it succeeds even for dead hosts.
    # TCP will get an immediate RST (True) or timeout/refused (False).
    for port in (22, 80, 443, 8080):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout((timeout_ms / 1000.0) / 4)
                s.connect((host, port))
            return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# SNMP probe
# ---------------------------------------------------------------------------

def snmp_check(host: str, auth, port: int, timeout: int, retries: int):
    """
    Probe sysName + sysDescr.  Tries v2c first, falls back to v1 if auth
    is a ('2c', community) tuple and v2c gets no reply.

    Returns (snmp_ok: bool, sys_name: str|None, sys_descr: str|None).
    """
    try:
        # Build transport ONCE and reuse for both OID fetches
        tgt = transport(host, port, timeout, retries)

        name = snmp_get(tgt, auth, OID["sysName"], timeout, retries)

        # v2c → v1 fallback
        if name is None and isinstance(auth, tuple) and str(auth[0]).lower() == "2c":
            v1_auth = ("1", auth[1])
            name = snmp_get(tgt, v1_auth, OID["sysName"], timeout, retries)
            if name:
                descr = snmp_get(tgt, v1_auth, OID["sysDescr"], timeout, retries)
                return True, str(name), str(descr) if descr else None
            return False, None, None

        if name:
            descr = snmp_get(tgt, auth, OID["sysDescr"], timeout, retries)
            return True, str(name), str(descr) if descr else None

    except Exception as exc:
        log.debug("snmp_check error for %s: %s", host, exc)

    return False, None, None


# ---------------------------------------------------------------------------
# Per-host worker
# ---------------------------------------------------------------------------

def _probe_one(ip_s: str, auth, port: int, timeout: int, retries: int,
               ping_timeout_ms: int) -> HostProbe:
    if not ping_host(ip_s, ping_timeout_ms):
        return HostProbe(ip=ip_s, ping_ok=False, snmp_ok=False)

    ok, sysn, sysd = snmp_check(ip_s, auth, port, timeout, retries)
    return HostProbe(ip=ip_s, ping_ok=True, snmp_ok=ok,
                     sys_name=sysn, sys_descr=sysd)


# ---------------------------------------------------------------------------
# CIDR sweep
# ---------------------------------------------------------------------------

def discover_cidr(
    cidr: str,
    auth,
    port: int = 161,
    timeout: int = 2,
    retries: int = 1,
    ping_timeout_ms: int = 800,
    workers: int = 100,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[HostProbe]:
    """
    Concurrent ping+SNMP discovery over a CIDR range.

    Args:
        cidr:            e.g. "192.168.1.0/24"
        auth:            ("2c", "public") | ("1", "public") | v3 dict
        port:            SNMP UDP port (default 161)
        timeout:         SNMP timeout per request in seconds
        retries:         SNMP retries per request
        ping_timeout_ms: ping wait in milliseconds
        workers:         max parallel threads (100 is safe for most OSes;
                         increase to 200 for large /16 scans on Linux)
        progress_cb:     optional callable(done: int, total: int) called
                         after each host completes — use for live UI updates

    Returns:
        List[HostProbe] sorted by IP address (stable order).
    """
    net = ip_network(cidr, strict=False)
    ips = [str(ip) for ip in net.hosts()]
    total = len(ips)

    if total == 0:
        return []

    # Cap workers to actual workload — no point spinning 100 threads for /30
    effective_workers = min(workers, total)

    results: List[HostProbe] = []
    done = 0

    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        future_to_ip = {
            pool.submit(_probe_one, ip_s, auth, port, timeout, retries, ping_timeout_ms): ip_s
            for ip_s in ips
        }

        # as_completed: results come back as soon as each host finishes,
        # not blocked behind slow hosts at the front of the list
        for future in as_completed(future_to_ip):
            done += 1
            try:
                results.append(future.result())
            except Exception as exc:
                ip_s = future_to_ip[future]
                log.warning("probe failed for %s: %s", ip_s, exc)
                results.append(HostProbe(ip=ip_s, ping_ok=False, snmp_ok=False))

            if progress_cb:
                try:
                    progress_cb(done, total)
                except Exception:
                    pass

    # Sort by IP for stable output
    results.sort(key=lambda p: tuple(int(o) for o in p.ip.split(".")))
    return results


# ---------------------------------------------------------------------------
# Web UI entry point  (called by job.py / scan_api.py)
# ---------------------------------------------------------------------------

def run(params: Dict[str, Any], progress=lambda *a, **k: None) -> Dict[str, Any]:
    """
    Entry point invoked by start_job().  Handles both CIDR discovery and
    single-host detailed scans.

    progress(percent, **meta) is the job.py callback.
    """
    target = params.get("target", "").strip()
    if not target:
        raise ValueError("No target specified")

    # --- Auth ---
    if params.get("v3"):
        v3 = params["v3"]
        auth = {
            "user":       v3.get("user", ""),
            "auth_key":   v3.get("auth_key"),
            "priv_key":   v3.get("priv_key"),
            "auth_proto": v3.get("auth_proto", "SHA"),
            "priv_proto": v3.get("priv_proto", "AES"),
        }
    else:
        version   = params.get("version", "2c")
        community = params.get("community", "public")
        auth = (version, community)

    port    = int(params.get("port", 161))
    timeout = int(params.get("timeout", 2))
    retries = int(params.get("retries", 1))
    workers = int(params.get("workers", 100))
    ping_ms = int(params.get("ping_timeout_ms", 800))

    # -----------------------------------------------------------------------
    # CIDR / network scan
    # -----------------------------------------------------------------------
    if "/" in target:
        log.info("Starting CIDR discovery on %s", target)
        progress(5, status="starting")

        net   = ip_network(target, strict=False)
        total = sum(1 for _ in net.hosts())

        # Map (done, total) → percent in range [10, 95] for live updates
        def _progress_cb(done: int, ttl: int):
            pct = 10 + int((done / ttl) * 85) if ttl else 95
            progress(pct, status="scanning", done=done, total=ttl)

        probes = discover_cidr(
            target, auth, port, timeout, retries,
            ping_timeout_ms=ping_ms,
            workers=workers,
            progress_cb=_progress_cb,
        )

        hosts_up   = [asdict(p) for p in probes if p.ping_ok]
        hosts_snmp = [asdict(p) for p in probes if p.snmp_ok]

        result = {
            "mode":          "discovery",
            "cidr":          target,
            "total_scanned": len(probes),
            "total_up":      len(hosts_up),
            "total_snmp":    len(hosts_snmp),
            # Include ALL ping-reachable hosts, not just SNMP ones —
            # useful to see printers, PCs, etc. that don't speak SNMP
            "hosts":         hosts_up,
        }

        save_scan(result, "discovery", target, "ok")
        progress(100, status="done")
        return result

    # -----------------------------------------------------------------------
    # Single host detailed scan
    # -----------------------------------------------------------------------
    else:
        log.info("Starting single-host scan on %s", target)
        progress(10, status="connecting")

        from snmp_magic.cli import scan_single_host   # avoid circular import

        progress(30, status="scanning")
        data = scan_single_host(
            target, auth, port, timeout, retries, collect=True
        )

        result = {"mode": "single", "host": data or {}}
        save_scan(result, "single", target, "ok")
        progress(100, status="done")
        return result
    
    