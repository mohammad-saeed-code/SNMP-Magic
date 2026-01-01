# snmp_magic/vendor/dlink.py
from __future__ import annotations
from collections import namedtuple
from typing import Dict, List, Optional, Set
import logging

from ..snmpio import snmp_walk, snmp_get
from ..ifmaps import build_ifindex_maps
from ..mibs import OID  # sysObjectID

log = logging.getLogger(__name__)

VendorVlanView = namedtuple("VendorVlanView", "vid name egress_ports untagged_ports")

# ---- D-Link detection ----
DL_ENT_PREFIX = "1.3.6.1.4.1.171"

# Confirmed model bases you provided (VLAN/PVID group root):
# These are the roots under which:
#   + ".6.1.1" -> dot1qVlanName
#   + ".6.1.2" -> dot1qVlanEgressPorts (PortList, LSB per octet)
#   + ".6.1.4" -> dot1qVlanUntaggedPorts (PortList, LSB per octet)
#   + ".7.1.1" -> dot1qVlanPvid (often indexed by bridgePort)
KNOWN_BASES = [
    "1.3.6.1.4.1.171.10.76.20.1.7",   # DGS-1210-28-CX
    "1.3.6.1.4.1.171.10.76.22.1.7",   # DGS-1210-52-CX
    "1.3.6.1.4.1.171.10.126.3.1.7",   # DGS-1500-28P-AX
]

# Optional: a few guarded guesses to catch close siblings without heavy tree walks.
NEARBY_GUESSES = [
    # DGS-1210 family (10.76.X.1.7)
    *[f"1.3.6.1.4.1.171.10.76.{x}.1.7" for x in (18, 19, 20, 21, 22, 24, 44)],
    # DGS-1500 family (10.126.X.1.7)
    *[f"1.3.6.1.4.1.171.10.126.{x}.1.7" for x in (2, 3, 4)],
]

# ---------------- helpers ----------------
def _bytes_or_empty(v) -> bytes:
    try:
        return bytes(v)
    except Exception:
        try:
            return v.asOctets()  # pysnmp OctetString
        except Exception:
            return b""

def _decode_portlist_lsb(octets, max_ports: Optional[int] = None) -> Set[int]:
    """
    D-Link vendor PortList encoding on these families: **LSB-first per octet**.
      bit0 of first octet => port1, bit1 => port2, ...
    """
    data = _bytes_or_empty(octets)
    if not data:
        return set()
    out: Set[int] = set()
    for i, b in enumerate(data):
        b = b if isinstance(b, int) else int(b)
        for bit in range(8):
            if b & (1 << bit):
                out.add(i * 8 + bit + 1)
    if max_ports:
        out = {p for p in out if p <= max_ports}
    return out

def _is_dlink(target, auth, timeout, retries) -> bool:
    try:
        soid = snmp_get(target, auth, OID["sysObjectID"], timeout, retries)
        return bool(soid) and str(soid).startswith(DL_ENT_PREFIX)
    except Exception:
        return False

def _has_any(root: str, target, auth, timeout, retries) -> bool:
    """True if walking root yields at least one row."""
    for _oid, _val in snmp_walk(target, auth, root, timeout, retries):
        return True
    return False

def _accept_base(base: str, target, auth, timeout, retries) -> Dict[str, bool]:
    """
    Probe a base. Accept if ANY of (names|egress|untagged) has rows.
    Return dict with which columns were present.
    """
    has_names = _has_any(base + ".6.1.1", target, auth, timeout, retries)
    has_egr   = _has_any(base + ".6.1.2", target, auth, timeout, retries)
    has_unt   = _has_any(base + ".6.1.4", target, auth, timeout, retries)
    return {"names": has_names, "egr": has_egr, "unt": has_unt, "ok": (has_names or has_egr or has_unt)}

def _candidate_bases(target, auth, timeout, retries) -> List[str]:
    """Ordered candidates: KNOWN_BASES first, then NEARBY_GUESSES (deduped)."""
    cands: List[str] = []
    for b in KNOWN_BASES:
        if b not in cands:
            cands.append(b)
    for g in NEARBY_GUESSES:
        if g not in cands:
            cands.append(g)
    return cands

# --------------- public API for vlan.py ---------------
def get_vendor_vlan_views(target, community, timeout, retries, max_ports=None) -> Optional[List[VendorVlanView]]:
    """
    Try D-Link vendor VLAN tables **first**.
    Accept a base if ANY of (names|egress|untagged) returns rows.
    If nothing vendor is found, return None so vlan.py falls back to Q-BRIDGE.
    """
    if not _is_dlink(target, community, timeout, retries):
        return None

    for base in _candidate_bases(target, community, timeout, retries):
        try:
            flags = _accept_base(base, target, community, timeout, retries)
            if not flags.get("ok"):
                continue

            name_oid = base + ".6.1.1"
            egr_oid  = base + ".6.1.2"
            unt_oid  = base + ".6.1.4"

            vlan: Dict[int, Dict[str, object]] = {}

            if flags.get("names"):
                for oid, val in snmp_walk(target, community, name_oid, timeout, retries):
                    try:
                        vid = int(oid.split(".")[-1])
                        nm = (str(val) or "").strip()
                        vlan.setdefault(vid, {})["name"] = nm if nm else f"VLAN-{vid}"
                    except Exception:
                        continue

            if flags.get("egr"):
                for oid, val in snmp_walk(target, community, egr_oid, timeout, retries):
                    try:
                        vid = int(oid.split(".")[-1])
                        vlan.setdefault(vid, {})["egress"] = _decode_portlist_lsb(val, max_ports=max_ports)
                    except Exception:
                        continue

            if flags.get("unt"):
                for oid, val in snmp_walk(target, community, unt_oid, timeout, retries):
                    try:
                        vid = int(oid.split(".")[-1])
                        vlan.setdefault(vid, {})["untagged"] = _decode_portlist_lsb(val, max_ports=max_ports)
                    except Exception:
                        continue

            if not vlan:
                # We accepted the base but all walks failed—try next base.
                continue

            views: List[VendorVlanView] = []
            for vid in sorted(vlan):
                entry = vlan[vid]
                name = entry.get("name", f"VLAN-{vid}")
                egr  = entry.get("egress", set()) or set()
                unt  = entry.get("untagged", set()) or set()
                views.append(VendorVlanView(vid=vid, name=str(name), egress_ports=set(egr), untagged_ports=set(unt)))

            log.info("D-Link vendor VLAN views accepted at base %s (names=%s egress=%s untagged=%s, vlans=%d)",
                     base, flags.get("names"), flags.get("egr"), flags.get("unt"), len(views))
            return views or None

        except Exception as e:
            log.debug("D-Link VLAN probe failed at base %s: %s", base, e)
            continue

    # No vendor tables found → let caller fall back to Q-BRIDGE
    return None

def get_vendor_pvid_map(target, community, timeout, retries) -> Optional[Dict[int, int]]:
    """
    Try D-Link vendor PVID table **first**.
    Translate bridgePort→ifIndex when needed.
    Return None to allow Q-BRIDGE fallback if vendor tables are absent.
    """
    if not _is_dlink(target, community, timeout, retries):
        return None

    for base in _candidate_bases(target, community, timeout, retries):
        try:
            pvid_oid = base + ".7.1.1"
            rows = list(snmp_walk(target, community, pvid_oid, timeout, retries))
            if not rows:
                continue

            raw: Dict[int, int] = {}
            for oid, val in rows:
                try:
                    tail = int(oid.split(".")[-1])  # often bridgePort
                    raw[tail] = int(val)
                except Exception:
                    continue
            if not raw:
                continue

            bridge_to_if, _ = build_ifindex_maps(target, community, timeout, retries)

            # Heuristic: if a significant chunk of keys exist in bridge_to_if, treat keys as bridgePorts
            hits = sum(1 for k in raw if k in bridge_to_if)
            if hits >= max(1, len(raw) // 3):
                out: Dict[int, int] = {}
                for bp, vid in raw.items():
                    ifidx = bridge_to_if.get(bp)
                    if ifidx:
                        out[int(ifidx)] = int(vid)
                if out:
                    log.info("D-Link vendor PVID (base %s) translated bridgePort→ifIndex entries=%d", base, len(out))
                    return out
                # fall through to assume keys are ifIndex if translation produced nothing (unlikely corner)

            # Assume keys are ifIndex already
            out = {int(k): int(v) for k, v in raw.items()}
            log.info("D-Link vendor PVID (base %s) entries=%d", base, len(out))
            return out

        except Exception as e:
            log.debug("D-Link PVID probe failed at base %s: %s", base, e)
            continue

    # No vendor PVID → let caller fall back to Q-BRIDGE
    return None
