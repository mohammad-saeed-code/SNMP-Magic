# snmp_magic/discovery.py
import sys
import logging
from ipaddress import ip_network
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor

from snmp_magic.snmpio import transport, snmp_get
from snmp_magic.mibs import OID
from snmp_magic.store import save_scan  # <--- NEW: Import store to save results

log = logging.getLogger(__name__)

@dataclass
class HostProbe:
    ip: str
    ping_ok: bool
    snmp_ok: bool
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None

# --- Existing Ping Helper Functions ---
def _ping_cmd(host: str, timeout_ms: int) -> list:
    import platform
    if sys.platform.startswith("win"):
        return ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        secs = max(1, int(round(timeout_ms / 1000)))
        return ["ping", "-c", "1", "-W", str(secs), host]

def ping_host(host: str, timeout_ms: int = 600) -> bool:
    import subprocess, platform
    try:
        cmd = _ping_cmd(host, timeout_ms)
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False

def snmp_check(ip: str, auth, port: int, timeout: int, retries: int):
    try:
        sysn = snmp_get(transport(ip, port, timeout, retries), auth, OID["sysName"], timeout, retries)
        if sysn is None:
            return False, None, None
        sysd = snmp_get(transport(ip, port, timeout, retries), auth, OID["sysDescr"], timeout, retries)
        return True, str(sysn), str(sysd)
    except Exception:
        return False, None, None

def _probe_worker(ip_s: str, auth, port: int, timeout: int, retries: int, ping_timeout_ms: int) -> HostProbe:
    if not ping_host(ip_s, ping_timeout_ms):
        return HostProbe(ip=ip_s, ping_ok=False, snmp_ok=False)
    ok, sysn, sysd = snmp_check(ip_s, auth, port, timeout, retries)
    return HostProbe(ip=ip_s, ping_ok=True, snmp_ok=ok, sys_name=sysn, sys_descr=sysd)

def discover_cidr(cidr: str, auth, port: int = 161, timeout: int = 2, retries: int = 1, ping_timeout_ms: int = 600, workers: int = 128) -> List[HostProbe]:
    net = ip_network(cidr, strict=False)
    ips = [str(ip) for ip in net.hosts()]
    
    # Limit workers if network is small
    workers = min(workers, len(ips)) if len(ips) > 0 else 1
    
    results: List[HostProbe] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_probe_worker, ip, auth, port, timeout, retries, ping_timeout_ms) for ip in ips]
        for f in futs:
            results.append(f.result())
    return results

# --- NEW: Main Entry Point for Web UI ---
def run(params: Dict[str, Any], progress=lambda *a, **k: None) -> Dict[str, Any]:
    """
    Main entry point called by job.py/discovery_entry.py.
    """
    target = params.get("target")
    if not target:
        raise ValueError("No target specified")

    # Auth setup
    version = params.get("version", "2c")
    community = params.get("community", "public")
    auth = (version, community)
    if params.get("v3"):
        # Basic V3 support unpacking
        v3 = params["v3"]
        auth = {
            "user": v3.get("user"),
            "auth_key": v3.get("auth_key"),
            "priv_key": v3.get("priv_key"),
            "auth_proto": v3.get("auth_proto", "SHA"),
            "priv_proto": v3.get("priv_proto", "AES"),
        }

    port = int(params.get("port", 161))
    timeout = int(params.get("timeout", 1))
    retries = int(params.get("retries", 1))

    log.info(f"Starting discovery on {target}")
    progress(10, status="scanning")

    # If it looks like a network (contains /), use discover_cidr
    if "/" in target:
        probes = discover_cidr(target, auth, port, timeout, retries)
        
        # Filter to only interesting hosts (SNMP OK)
        hosts = [asdict(p) for p in probes if p.snmp_ok]
        
        result = {"mode": "discovery", "cidr": target, "hosts": hosts, "total_scanned": len(probes)}
        
        # Save to DB
        save_scan(result, "discovery", target, "ok")
        progress(100, status="done")
        return result

    else:
        # Single Host Mode - Use the detailed scanner from CLI
        # Local import to avoid circular dependency
        from snmp_magic.cli import scan_single_host
        
        progress(30, status="scanning_host")
        data = scan_single_host(target, auth, port, timeout, retries, collect=True)
        
        result = {"mode": "single", "host": data}
        
        # Save to DB
        save_scan(result, "single", target, "ok")
        progress(100, status="done")
        return result