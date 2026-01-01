from collections import defaultdict
import logging
from .mibs import OID
from .snmpio import snmp_walk
from .ifmaps import build_ifindex_maps

log = logging.getLogger(__name__)

# --- Safe LLDP decoding helpers ---
def _is_printable_ascii(b: bytes) -> bool:
    return all(32 <= x <= 126 for x in b)

def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in (b or b""))

def _fmt_text(raw) -> str:
    """Decode OctetString safely; fall back to hex."""
    try:
        b = bytes(raw)
    except Exception:
        try:
            b = str(raw).encode("utf-8", "ignore")
        except Exception:
            return str(raw)

    if _is_printable_ascii(b):
        return b.decode("ascii", "ignore")

    # try utf-8 then latin-1, but only if printable post-decode
    try:
        s = b.decode("utf-8", "ignore")
        if _is_printable_ascii(s.encode("utf-8", "ignore")):
            return s
    except Exception:
        pass

    s = b.decode("latin-1", "ignore")
    if _is_printable_ascii(s.encode("latin-1", "ignore")):
        return s

    return "0x" + b.hex()

def _fmt_lldp_id(raw_value, subtype: int) -> str:
    """
    Format LLDP PortId/ChassisId by subtype:
      3=macAddress, 4=networkAddress, 1/5/6/7 textual-ish (chassis/ifName/ifAlias/local).
      Otherwise: printable text or hex.
    """
    try:
        b = bytes(raw_value)
    except Exception:
        try:
            b = bytes(str(raw_value), "latin-1", errors="ignore")
        except Exception:
            return str(raw_value)

    if subtype in (3, 4):
        # mac/networkAddress → hex form (mac prettified when 6/8 bytes)
        if len(b) in (6, 8):
            return _fmt_mac(b)
        return "0x" + b.hex()

    if subtype in (1, 5, 6, 7):  # include 'local' as potentially textual
        return _fmt_text(b)

    # Fallback: if printable treat as text, else hex
    if _is_printable_ascii(b):
        try:
            return b.decode("utf-8", "ignore")
        except Exception:
            return b.decode("latin-1", "ignore")
    return "0x" + b.hex()


def get_lldp_neighbors(target, community, timeout, retries):
    log.debug("Collecting LLDP neighbors (label-centric view)")
    bridge_to_if, if_labels = build_ifindex_maps(target, community, timeout, retries)
    neighbors = defaultdict(list)

    # --- Walk LLDP tables ---
    rem_sys = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemSysName"], timeout, retries):
        parts = oid.split('.')
        local_port = int(parts[-2])
        rem_sys[local_port] = str(val)

    rem_portid = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemPortId"], timeout, retries):
        parts = oid.split('.')
        local_port = int(parts[-2])
        rem_portid[local_port] = val  # keep bytes for formatting

    rem_portdesc = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemPortDesc"], timeout, retries):
        parts = oid.split('.')
        local_port = int(parts[-2])
        rem_portdesc[local_port] = _fmt_text(val)

    rem_pid_sub = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemPortIdSubtype"], timeout, retries):
        parts = oid.split('.')
        local_port = int(parts[-2])
        rem_pid_sub[local_port] = int(val)

    # Optional: if sysName is empty, fall back to chassis id string
    rem_chassis = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemChassisId"], timeout, retries):
        parts = oid.split('.')
        local_port = int(parts[-2])
        rem_chassis[local_port] = val

    rem_ch_sub = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemChassisIdSubtype"], timeout, retries):
        parts = oid.split('.')
        local_port = int(parts[-2])
        rem_ch_sub[local_port] = int(val)

    # --- Build label-centric map ---
    all_ports = set().union(rem_sys, rem_portid, rem_portdesc, rem_pid_sub, rem_chassis, rem_ch_sub)
    for local_port in all_ports:
        label = if_labels.get(local_port)
        if not label:
            ifidx = bridge_to_if.get(local_port)
            label = if_labels.get(ifidx) if ifidx else None
        label = label or f"port{local_port}"

        sysn = rem_sys.get(local_port, "")
        if not sysn:
            ch_sub = rem_ch_sub.get(local_port, 0)
            ch_id = rem_chassis.get(local_port, b"")
            sysn = _fmt_lldp_id(ch_id, ch_sub) if ch_id else "?"

        pid_sub = rem_pid_sub.get(local_port, 0)
        pid_val = rem_portid.get(local_port, b"")
        pid_str = _fmt_lldp_id(pid_val, pid_sub) if pid_val is not None else "?"

        pdesc = rem_portdesc.get(local_port, "")

        neighbors[label].append({
            "sysName": sysn,
            "portId": pid_str,
            "portDesc": pdesc,
        })

    log.debug("LLDP neighbor sets: %d", len(neighbors))
    return dict(neighbors)
