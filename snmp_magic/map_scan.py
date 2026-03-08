# snmp_magic/map_scan.py
"""
Network topology discovery using ping sweep + reverse DNS + traceroute.
No root/admin privileges required.

Pipeline:
  1. Ping sweep  → list of live IPs
  2. rDNS        → IP → hostname (parallel)
  3. Traceroute  → IP → list of hops → infer topology edges
  4. DB enrich   → merge with known SNMP device data
  5. OUI lookup  → vendor name from MAC prefix
"""

from __future__ import annotations

import logging
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from ipaddress import ip_network
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

MAX_HOPS       = 20
TRACE_WORKERS  = 30   # traceroutes are slow — limit parallelism
DNS_WORKERS    = 100  # DNS is fast
PING_WORKERS   = 100

# ---------------------------------------------------------------------------
# OUI vendor lookup  (built-in mini table for the most common prefixes)
# Full lookup would need a file — this covers 80% of typical office networks
# ---------------------------------------------------------------------------
_OUI: Dict[str, str] = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",
    "00:1a:11": "Google",       "f4:f5:d8": "Google",
    "ac:e2:d3": "HP",           "3c:d9:2b": "HP",
    "00:1b:63": "Apple",        "f8:ff:c2": "Apple",
    "a4:c3:f0": "Apple",        "dc:a4:ca": "Apple",
    "00:1c:42": "Parallels",    "00:16:3e": "Xen",
    "52:54:00": "QEMU/KVM",     "00:15:5d": "Microsoft Hyper-V",
    "00:50:f2": "Microsoft",    "28:d2:44": "Microsoft",
    "00:e0:4c": "Realtek",      "00:1d:60": "Cisco",
    "00:0f:34": "Cisco",        "00:1e:14": "Cisco",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:04:4b": "NVIDIA",
    "00:26:b9": "Dell",         "f8:db:88": "Dell",
    "00:14:22": "Dell",         "54:bf:64": "Intel",
    "00:23:14": "Intel",        "8c:8d:28": "Intel",
    "78:2b:cb": "Intel",        "00:1b:21": "Intel",
}


def mac_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.lower().replace("-", ":")[0:8]
    return _OUI.get(prefix)


# ---------------------------------------------------------------------------
# Ping (reuse from discovery.py logic, self-contained here)
# ---------------------------------------------------------------------------

def _ping(host: str, timeout_ms: int = 800) -> bool:
    system = platform.system().lower()
    try:
        if system.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), host]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_ms)), host]
        else:
            sec = max(1, round(timeout_ms / 1000))
            cmd = ["ping", "-c", "1", "-W", str(sec), host]

        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           timeout=(timeout_ms / 1000) + 2)
        if r.returncode == 0:
            return True
    except Exception:
        pass

    # TCP fallback
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
# Reverse DNS
# ---------------------------------------------------------------------------

def _rdns(ip: str) -> Optional[str]:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        # Strip if it's just the IP written as a hostname (some ISPs do this)
        if hostname == ip or hostname.replace("-", ".").endswith(ip):
            return None
        return hostname
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Traceroute (cross-platform, no root needed for ICMP on Windows,
# uses UDP on Linux which also works unprivileged for path discovery)
# ---------------------------------------------------------------------------

def _traceroute(host: str, max_hops: int = MAX_HOPS) -> List[Optional[str]]:
    """
    Returns ordered list of hop IPs (None = timed-out hop / no reply).
    Stops as soon as destination is reached or max_hops exceeded.
    """
    system = platform.system().lower()

    if system.startswith("win"):
        # tracert -d (no DNS) -h max_hops -w 1000ms
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host]
    elif system == "darwin":
        # macOS traceroute -n (no DNS) -m max_hops -w 2 (2s wait)
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", host]
    else:
        # Linux traceroute -n -m max_hops -w 2
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", host]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=max_hops * 4,   # generous timeout
            text=True,
        )
        return _parse_traceroute(result.stdout, host)
    except FileNotFoundError:
        log.warning("traceroute/tracert binary not found")
        return []
    except subprocess.TimeoutExpired:
        log.debug("traceroute to %s timed out", host)
        return []
    except Exception as exc:
        log.debug("traceroute error for %s: %s", host, exc)
        return []


# IP pattern
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

def _parse_traceroute(output: str, destination: str) -> List[Optional[str]]:
    """
    Parse traceroute/tracert stdout into ordered list of hop IPs.
    * means timed out → None in the list.
    Stops at destination.
    """
    hops: List[Optional[str]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Skip headers (Windows: "Tracing route to...", Linux: "traceroute to...")
        if re.match(r"^[Tt]race", line):
            continue
        # Skip "over a maximum of..." lines
        if "maximum" in line.lower() or "over" in line.lower():
            continue

        # Check for timeout (all * on the line)
        if re.match(r"^\d+\s+[\*\s]+$", line):
            hops.append(None)
            continue

        # Extract IPs from the line
        ips = _IP_RE.findall(line)
        if not ips:
            continue

        # First number on line is the hop count — skip it if it looks like one
        hop_ip = None
        for ip in ips:
            # Skip hop-number-looking IPs (single digit masquerading as IP is rare)
            octets = [int(o) for o in ip.split(".")]
            if octets[0] == 0:
                continue
            hop_ip = ip
            break

        if hop_ip:
            hops.append(hop_ip)
            # Stop if we've reached the destination
            if hop_ip == destination:
                break
        else:
            hops.append(None)

    return hops


# ---------------------------------------------------------------------------
# Node & Edge data structures
# ---------------------------------------------------------------------------

@dataclass
class MapNode:
    id:       str                        # IP address
    label:    str                        # display name
    hostname: Optional[str]  = None
    sys_name: Optional[str]  = None
    sys_descr:Optional[str]  = None
    vendor:   Optional[str]  = None
    mac:      Optional[str]  = None
    node_type:str            = "host"   # "host" | "router" | "gateway" | "server"
    alive:    bool           = True


@dataclass
class MapEdge:
    source: str   # IP
    target: str   # IP
    kind:   str = "trace"   # "trace" | "lldp"


# ---------------------------------------------------------------------------
# Main topology builder
# ---------------------------------------------------------------------------

def build_topology(
    cidr: str,
    ping_timeout_ms: int = 800,
    max_hops: int = MAX_HOPS,
    progress_cb: Optional[Callable[[int, str], None]] = None,
    db_devices: Optional[Dict[str, Dict]] = None,  # ip → {sys_name, sys_descr, mac}
) -> Dict[str, Any]:
    """
    Full topology scan: ping → rDNS → traceroute → graph assembly.

    Returns dict with:
      nodes: list of MapNode dicts
      edges: list of MapEdge dicts
      scanned_at: ISO timestamp
      cidr: the input CIDR
    """

    def _progress(pct: int, msg: str):
        if progress_cb:
            try:
                progress_cb(pct, msg)
            except Exception:
                pass

    db_devices = db_devices or {}

    # ------------------------------------------------------------------
    # Stage 1: Ping sweep
    # ------------------------------------------------------------------
    _progress(5, "ping_sweep")
    net  = ip_network(cidr, strict=False)
    ips  = [str(ip) for ip in net.hosts()]
    total = len(ips)

    live: List[str] = []
    done = 0

    with ThreadPoolExecutor(max_workers=min(PING_WORKERS, total)) as pool:
        futs = {pool.submit(_ping, ip, ping_timeout_ms): ip for ip in ips}
        for f in as_completed(futs):
            done += 1
            ip = futs[f]
            try:
                if f.result():
                    live.append(ip)
            except Exception:
                pass
            pct = 5 + int((done / total) * 25)
            _progress(pct, f"ping {done}/{total}")

    log.info("Ping sweep: %d/%d hosts alive", len(live), total)
    _progress(30, "rdns")

    # ------------------------------------------------------------------
    # Stage 2: Reverse DNS (parallel)
    # ------------------------------------------------------------------
    rdns_map: Dict[str, Optional[str]] = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futs = {pool.submit(_rdns, ip): ip for ip in live}
        for f in as_completed(futs):
            ip = futs[f]
            try:
                rdns_map[ip] = f.result()
            except Exception:
                rdns_map[ip] = None

    _progress(40, "traceroute")

    # ------------------------------------------------------------------
    # Stage 3: Traceroute (parallel, limited workers — these are slow)
    # ------------------------------------------------------------------
    traces: Dict[str, List[Optional[str]]] = {}
    done = 0
    n_live = len(live)

    with ThreadPoolExecutor(max_workers=min(TRACE_WORKERS, max(1, n_live))) as pool:
        futs = {pool.submit(_traceroute, ip, max_hops): ip for ip in live}
        for f in as_completed(futs):
            done += 1
            ip = futs[f]
            try:
                traces[ip] = f.result()
            except Exception:
                traces[ip] = []
            pct = 40 + int((done / max(n_live, 1)) * 50)
            _progress(pct, f"traceroute {done}/{n_live}")

    _progress(90, "building_graph")

    # ------------------------------------------------------------------
    # Stage 4: Build graph
    # ------------------------------------------------------------------
    nodes: Dict[str, MapNode] = {}
    edges_set: set = set()   # (source, target) dedup
    edges: List[MapEdge] = []

    def _get_or_create_node(ip: str) -> MapNode:
        if ip not in nodes:
            db  = db_devices.get(ip, {})
            mac = db.get("mac")
            sn  = db.get("sys_name")
            sd  = db.get("sys_descr")
            hn  = rdns_map.get(ip)
            vnd = mac_vendor(mac)

            # Best available label
            label = sn or hn or (f"{ip} [{vnd}]" if vnd else ip)

            nodes[ip] = MapNode(
                id=ip, label=label,
                hostname=hn, sys_name=sn, sys_descr=sd,
                vendor=vnd, mac=mac,
                node_type="host",
                alive=(ip in live),
            )
        return nodes[ip]

    def _add_edge(src: str, dst: str, kind: str = "trace"):
        key = (src, dst)
        if key not in edges_set:
            edges_set.add(key)
            edges.append(MapEdge(source=src, target=dst, kind=kind))

    # Create nodes for all live hosts
    for ip in live:
        _get_or_create_node(ip)

    # Build edges from traceroute paths
    # Also infer router nodes from intermediate hops
    for dest_ip, hops in traces.items():
        prev: Optional[str] = None
        for hop_ip in hops:
            if hop_ip is None:
                prev = None  # reset on timeout hop — don't connect across gaps
                continue

            node = _get_or_create_node(hop_ip)

            # If this hop is NOT in our live list it's a router/gateway
            if hop_ip not in live:
                node.node_type = "router"
                node.alive = True  # it responded to traceroute

            if prev is not None:
                _add_edge(prev, hop_ip)
            prev = hop_ip

        # Final edge: last known hop → destination
        valid_hops = [h for h in hops if h is not None]
        if valid_hops and valid_hops[-1] != dest_ip:
            _add_edge(valid_hops[-1], dest_ip)

    # Tag likely gateways: nodes that appear as first hop for many traces
    first_hops: Dict[str, int] = {}
    for hops in traces.values():
        for h in hops:
            if h:
                first_hops[h] = first_hops.get(h, 0) + 1
                break

    for ip, count in first_hops.items():
        if count >= 3 and ip in nodes:   # first hop for 3+ hosts → gateway
            nodes[ip].node_type = "gateway"

    _progress(100, "done")

    return {
        "cidr":       cidr,
        "scanned_at": datetime.utcnow().isoformat(),
        "nodes":      [asdict(n) for n in nodes.values()],
        "edges":      [asdict(e) for e in edges],
        "stats": {
            "total_ips":   total,
            "alive":       len(live),
            "nodes":       len(nodes),
            "edges":       len(edges),
        }
    }