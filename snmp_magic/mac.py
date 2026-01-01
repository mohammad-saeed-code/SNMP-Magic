# snmp_magic/mac.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import logging

from .mibs import OID
from .snmpio import snmp_walk
from .ifmaps import build_ifindex_maps


_OUI_CACHE: dict[str, Dict[str, str]] = {}

log = logging.getLogger(__name__)

IGNORED_MAC_PREFIXES = (
    b"\xff\xff\xff\xff\xff\xff",                 # broadcast
    bytes.fromhex("0180c2000000"),               # 01:80:C2:00:00:00 (STP/LACP/LLDP groups)
)
IGNORED_MULTICAST_PREFIXES = (
    bytes.fromhex("01000c"),  # Cisco CDP/VTP
    bytes.fromhex("3333"),    # IPv6 multicast
)

@dataclass
class FdbEntry:
    mac: str
    ifIndex: Optional[int]
    vlan: Optional[int]
    status: str                 # other|invalid|learned|self|mgmt
    vendor: Optional[str] = None


def _mac_bytes(v) -> bytes:
    if v is None:
        return b""
    try:
        return bytes(v)
    except Exception:
        try:
            s = str(v).replace(" ", "").replace(":", "").replace("-", "")
            return bytes.fromhex(s)
        except Exception:
            return b""


def _mac_to_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b) if b else ""


def _is_ignored(b: bytes) -> bool:
    if not b or len(b) < 6:
        return True
    if b in IGNORED_MAC_PREFIXES:
        return True
    # multicast
    if (b[0] & 1) == 1 and b[:3] in IGNORED_MULTICAST_PREFIXES:
        return True
    return False


def _status_name(code: int) -> str:
    # dot1dTpFdbStatus: other(1), invalid(2), learned(3), self(4), mgmt(5)
    return {1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}.get(code, str(code))


# ---------------- OUI DB ----------------
def load_oui_db(path: Optional[str]) -> Dict[str, str]:
    """
    Load a simple file where each line is 'OUI,Vendor' (OUI as AABBCC or AA:BB:CC).
    Returns a tiny seed if path is None/unreadable. Keys are 'aa:bb:cc'.
    """
    seed = {
        "00:50:56": "VMware, Inc.",
        "00:1c:bf": "Cisco Systems, Inc",
        "00:1a:1e": "Hewlett Packard",
        "44:65:0d": "Ubiquiti Networks",
        "b8:27:eb": "Raspberry Pi Trading",
    }
    if not path:
        return seed
    try:
        db: Dict[str, str] = {}
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.replace("\t", ",").split(",") if p.strip()]
                if not parts:
                    continue
                oui = parts[0].lower().replace("-", ":").replace(".", ":")
                if len(oui) == 6:  # AABBCC
                    oui = ":".join(oui[i:i+2] for i in range(0, 6, 2))
                vendor = parts[1] if len(parts) >= 2 else "Unknown"
                if len(oui) == 8:  # 'aa:bb:cc'
                    db[oui] = vendor
        return db or seed
    except Exception:
        log.warning("Failed to load OUI DB from %s; using seed entries", path)
        return seed


def _vendor_from_mac(b: bytes, oui_db: Dict[str, str]) -> Optional[str]:
    if not b or len(b) < 3:
        return None
    key = ":".join(f"{x:02x}" for x in b[:3])
    return oui_db.get(key)


# -------------- Collectors --------------
def _walk_qbridge_fdb(target, auth, timeout, retries) -> List[Tuple[int, bytes, int]]:
    """
    Return (vlan, mac_bytes, status_code) using dot1qTpFdb*.
    Index tail pattern: <VID>.<m1>.<m2>.<m3>.<m4>.<m5>.<m6>
    """
    out: Dict[Tuple[int, bytes], int] = {}

    def parse_idx(oid: str) -> Optional[Tuple[int, bytes]]:
        try:
            parts = [int(x) for x in oid.split(".")[-7:]]
            return parts[0], bytes(parts[1:7])
        except Exception:
            return None

    # Status rows
    for oid, val in snmp_walk(target, auth, OID["dot1qTpFdbStatus"], timeout, retries):
        idx = parse_idx(oid)
        if idx:
            out[idx] = int(val)

    # Ensure we capture entries that only have Port rows
    for oid, _val in snmp_walk(target, auth, OID["dot1qTpFdbPort"], timeout, retries):
        idx = parse_idx(oid)
        if idx:
            out.setdefault(idx, 1)  # other

    return [(vid, macb, st) for (vid, macb), st in out.items()]


def _walk_bridge_fdb(target, auth, timeout, retries) -> List[Tuple[bytes, int]]:
    """
    Return (mac_bytes, status_code) using dot1dTpFdb* (no VLAN).
    """
    rows: Dict[bytes, int] = {}

    for oid, val in snmp_walk(target, auth, OID["dot1dTpFdbStatus"], timeout, retries):
        try:
            mac6 = bytes(int(x) for x in oid.split(".")[-6:])
            rows[mac6] = int(val)
        except Exception:
            continue

    if not rows:
        for _oid, mac_val in snmp_walk(target, auth, OID["dot1dTpFdbAddress"], timeout, retries):
            mb = _mac_bytes(mac_val)
            if mb:
                rows[mb] = 1

    return list(rows.items())


def get_fdb_entries(
    target,
    auth,
    timeout: int,
    retries: int,
    include_non_dynamic: bool = False,
    oui_db_path: Optional[str] = None,
) -> List[FdbEntry]:
    """
    Collect FDB entries from Q-BRIDGE if available, else BRIDGE.
    - Maps bridgePort -> ifIndex.
    - Filters broadcast & common multicast protocol MACs.
    - By default hides non-dynamic entries (status not in learned/self/mgmt).
    """
    bridge_to_if, _ = build_ifindex_maps(target, auth, timeout, retries)

    q_rows = _walk_qbridge_fdb(target, auth, timeout, retries)
    oui_db = load_oui_db(oui_db_path)
    entries: List[FdbEntry] = []

    if q_rows:
        # Map (vid,mac) -> bridgePort
        port_map: Dict[Tuple[int, bytes], int] = {}
        for oid, val in snmp_walk(target, auth, OID["dot1qTpFdbPort"], timeout, retries):
            try:
                parts = [int(x) for x in oid.split(".")[-7:]]
                vid, mac6 = parts[0], bytes(parts[1:7])
                port_map[(vid, mac6)] = int(val)
            except Exception:
                continue

        for (vid, macb, st_code) in q_rows:
            if _is_ignored(macb):
                continue
            if not include_non_dynamic and st_code not in (3, 4, 5):
                continue
            bport = port_map.get((vid, macb))
            ifidx = bridge_to_if.get(bport) if bport else None
            vendor = _vendor_from_mac(macb, oui_db)
            entries.append(FdbEntry(
                mac=_mac_to_str(macb), ifIndex=ifidx, vlan=int(vid),
                status=_status_name(st_code), vendor=vendor
            ))
        log.info("FDB(Q-BRIDGE): entries=%d", len(entries))
        return entries

    # Fallback: classic BRIDGE-MIB
    br_rows = _walk_bridge_fdb(target, auth, timeout, retries)
    port_map_b: Dict[bytes, int] = {}
    for oid, val in snmp_walk(target, auth, OID["dot1dTpFdbPort"], timeout, retries):
        try:
            mac6 = bytes(int(x) for x in oid.split(".")[-6:])
            port_map_b[mac6] = int(val)
        except Exception:
            continue

    for macb, st_code in br_rows:
        if _is_ignored(macb):
            continue
        if not include_non_dynamic and st_code not in (3, 4, 5):
            continue
        bport = port_map_b.get(macb)
        ifidx = bridge_to_if.get(bport) if bport else None
        vendor = _vendor_from_mac(macb, oui_db)
        entries.append(FdbEntry(
            mac=_mac_to_str(macb), ifIndex=ifidx, vlan=None,
            status=_status_name(st_code), vendor=vendor
        ))
    log.info("FDB(BRIDGE): entries=%d", len(entries))
    return entries
