# snmp_magic/discovery.py
import sys
import subprocess
from ipaddress import ip_network
from dataclasses import dataclass
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform, socket

from .snmpio import transport
from .mibs import OID
from .snmpio import snmp_get


@dataclass
class HostProbe:
    ip: str
    ping_ok: bool
    snmp_ok: bool
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None


def _ping_cmd(host: str, timeout_ms: int) -> list:
    if sys.platform.startswith("win"):
        # Windows ping: -n 1 (one echo), -w timeout in ms
        return ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        # Linux/mac: -c 1 (one echo), -W timeout in seconds
        secs = max(1, int(round(timeout_ms / 1000)))
        return ["ping", "-c", "1", "-W", str(secs), host]


def ping_host(host: str, timeout_ms: int = 600) -> bool:
    """Cross-platform ping. Returns True if a reply is received within timeout."""
    try:
        system = platform.system().lower()
        if system.startswith("win"):
            # Windows: -n 1 (count 1), -w <ms> (timeout per reply in ms)
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), host]
        elif system == "darwin":
            # macOS: -c 1 (count 1), -W <ms> (wait in ms)
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_ms)), host]
        else:
            # Linux/others: -c 1 (count 1), -W <sec> (wait in seconds)
            sec = max(1, int(round(timeout_ms / 1000.0)))
            cmd = ["ping", "-c", "1", "-W", str(sec), host]

        res = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if res.returncode == 0:
            return True
    except Exception:
        pass

    # Fallback: UDP "connect" probe to 161 (doesn't send, but fails fast on bad routes)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_ms / 1000.0)
        s.connect((host, 161))
        s.close()
        return True
    except Exception:
        return False


def snmp_check(host: str, auth, port: int, timeout: int, retries: int):
    """Lightweight SNMP probe using sysName/sysDescr. Falls back to v1 if v2c fails."""
    try:
        tgt = transport(host, port)
        name = snmp_get(tgt, auth, OID["sysName"], timeout, retries)
        if not name and isinstance(auth, tuple) and str(auth[0]).lower() == "2c":
            # Fallback to v1
            name = snmp_get(tgt, ("1", auth[1]), OID["sysName"], timeout, retries)
            if name:
                descr = snmp_get(tgt, ("1", auth[1]), OID["sysDescr"], timeout, retries)
                return True, str(name), str(descr) if descr else None
            return False, None, None
        if name:
            descr = snmp_get(tgt, auth, OID["sysDescr"], timeout, retries)
            return True, str(name), str(descr) if descr else None
    except Exception:
        pass
    return False, None, None



def _probe_one(ip_s: str, auth, port: int, timeout: int, retries: int, ping_timeout_ms: int) -> HostProbe:
    if not ping_host(ip_s, ping_timeout_ms):
        return HostProbe(ip=ip_s, ping_ok=False, snmp_ok=False)
    ok, sysn, sysd = snmp_check(ip_s, auth, port, timeout, retries)
    return HostProbe(ip=ip_s, ping_ok=True, snmp_ok=ok, sys_name=sysn, sys_descr=sysd)


def discover_cidr(
    cidr: str,
    auth,
    port: int = 161,
    timeout: int = 2,
    retries: int = 1,
    ping_timeout_ms: int = 600,
    workers: int = 128,
) -> List[HostProbe]:
    """
    Concurrent ping+SNMP discovery over a CIDR.
    - workers: maximum parallel probes (I/O-bound; 64–256 tends to be safe)
    """
    net = ip_network(cidr, strict=False)
    ips = [str(ip) for ip in net.hosts()]
    results: List[HostProbe] = []

    if workers < 1:
        workers = 1

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [
            ex.submit(_probe_one, ip_s, auth, port, timeout, retries, ping_timeout_ms)
            for ip_s in ips
        ]
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                # Keep discovery resilient even if a worker throws
                pass

    # Stable order by IP for nicer printing
    try:
        results.sort(key=lambda p: list(map(int, p.ip.split("."))))
    except Exception:
        results.sort(key=lambda p: p.ip)

    return results
