# snmp_magic/interfaces.py
from collections import defaultdict, namedtuple
import logging
from .mibs import OID
from .snmpio import snmp_get, snmp_walk
from .ifmaps import build_ifindex_maps

log = logging.getLogger(__name__)

InterfaceRow = namedtuple("InterfaceRow", [
    "ifIndex", "name", "alias", "admin", "oper", "speed", "mtu", "duplex",
    "pvid", "in_bytes", "out_bytes", "in_err", "out_err", "mac", "last_change", "neighbors"
])

# -----------------------------
# Generic SNMP walk helpers
# -----------------------------
def _walk_map_int(target, community, oid, timeout, retries):
    out = {}
    for o, v in snmp_walk(target, community, oid, timeout, retries):
        try:
            out[int(o.split('.')[-1])] = int(v)
        except Exception:
            continue
    log.debug("Walk int map oid=%s entries=%d", oid, len(out))
    return out

def _walk_map_str(target, community, oid, timeout, retries):
    out = {}
    for o, v in snmp_walk(target, community, oid, timeout, retries):
        try:
            out[int(o.split('.')[-1])] = str(v)
        except Exception:
            continue
    log.debug("Walk str map oid=%s entries=%d", oid, len(out))
    return out

def _walk_map_octets(target, community, oid, timeout, retries):
    out = {}
    for o, v in snmp_walk(target, community, oid, timeout, retries):
        try:
            out[int(o.split('.')[-1])] = bytes(v)
        except Exception:
            continue
    log.debug("Walk octets map oid=%s entries=%d", oid, len(out))
    return out

# -----------------------------
# (Formatting helpers unchanged)
# -----------------------------
def _format_speed(ifHighSpeed_mbps, ifSpeed_bps):
    if ifHighSpeed_mbps and ifHighSpeed_mbps > 0:
        return f"{ifHighSpeed_mbps} Mb/s"
    if ifSpeed_bps and ifSpeed_bps > 0:
        return f"{max(1, int(ifSpeed_bps / 1_000_000))} Mb/s"
    return "unknown"

def _format_mac(octets):
    if not octets:
        return ""
    return ":".join(f"{b:02x}" for b in octets)

def _timeticks_to_age_str(ticks, sysuptime_ticks):
    try:
        if ticks is None or sysuptime_ticks is None:
            return ""
        age_ticks = sysuptime_ticks - ticks
        if age_ticks < 0:
            age_ticks = 0
        secs = int(age_ticks / 100)
        d = secs // 86400
        h = (secs % 86400) // 3600
        m = (secs % 3600) // 60
        s = secs % 60
        parts = []
        if d:
            parts.append(f"{d}d")
        if h or parts:
            parts.append(f"{h}h")
        if m or parts:
            parts.append(f"{m}m")
        parts.append(f"{s}s")
        return " ".join(parts) + " ago"
    except Exception:
        return ""

def _duplex_name(code):
    return {1: "unknown", 2: "half", 3: "full"}.get(code, "unknown")

# -----------------------------
# LLDP neighbor decoding (fixed)
# -----------------------------
# (unchanged helper functions) …

def _is_printable_ascii(b: bytes) -> bool:
    return all(32 <= x <= 126 for x in b)

def _fmt_lldp_text(raw):
    """Decode LLDP OctetStrings safely; fall back to hex if not printable."""
    try:
        b = bytes(raw)
    except Exception:
        # last resort: turn whatever it is into bytes
        try:
            b = str(raw).encode("utf-8", "ignore")
        except Exception:
            return str(raw)

    # Printable ASCII straight away?
    if _is_printable_ascii(b):
        return b.decode("ascii", "ignore")

    # Try UTF-8
    try:
        s = b.decode("utf-8", "ignore")
        if _is_printable_ascii(s.encode("utf-8", "ignore")):
            return s
    except Exception:
        pass

    # Try Latin-1
    s = b.decode("latin-1", "ignore")
    if _is_printable_ascii(s.encode("latin-1", "ignore")):
        return s

    # Give up: show hex so it’s readable and deterministic
    return "0x" + b.hex()


def _fmt_mac_lldp(b: bytes) -> str:
    if not b:
        return ""
    return ":".join(f"{x:02x}" for x in b)

def _fmt_lldp_id(raw_value, subtype: int) -> str:
    # (same implementation as before)
    try:
        b = bytes(raw_value)
    except Exception:
        try:
            b = bytes(str(raw_value), "latin-1", errors="ignore")
        except Exception:
            return str(raw_value)
    if subtype in (3, 4):
        if len(b) in (6, 8):
            return _fmt_mac_lldp(b)
        return "0x" + b.hex()
    if subtype in (1, 5, 6, 7):
        try:
            s = b.decode("utf-8", errors="strict")
            if _is_printable_ascii(b):
                return s
        except Exception:
            pass
        s = b.decode("latin-1", errors="ignore")
        return s if _is_printable_ascii(s.encode("latin-1", errors="ignore")) else "0x" + b.hex()
    if _is_printable_ascii(b):
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return b.decode("latin-1", errors="ignore")
    return "0x" + b.hex()

def get_neighbors_by_ifindex(target, community, timeout, retries):
    neighbors = {}
    rem_sys = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemSysName"], timeout, retries):
        local = int(oid.split('.')[-2])
        rem_sys[local] = str(val)

    rem_pid = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemPortId"], timeout, retries):
        local = int(oid.split('.')[-2])
        rem_pid[local] = val

    rem_pdesc = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemPortDesc"], timeout, retries):
        local = int(oid.split('.')[-2])
        rem_pdesc[local] = _fmt_lldp_text(val)

    rem_pid_sub = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemPortIdSubtype"], timeout, retries):
        local = int(oid.split('.')[-2])
        rem_pid_sub[local] = int(val)

    rem_chassis = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemChassisId"], timeout, retries):
        local = int(oid.split('.')[-2])
        rem_chassis[local] = val

    rem_ch_sub = {}
    for oid, val in snmp_walk(target, community, OID["lldpRemChassisIdSubtype"], timeout, retries):
        local = int(oid.split('.')[-2])
        rem_ch_sub[local] = int(val)

    bridge_to_if, _ = build_ifindex_maps(target, community, timeout, retries)

    all_keys = set().union(rem_sys, rem_pid, rem_pdesc, rem_pid_sub, rem_chassis, rem_ch_sub)
    for local in all_keys:
        ifidx = local if local in bridge_to_if.values() else bridge_to_if.get(local, local)
        sysn = rem_sys.get(local, "")
        if not sysn:
            ch_sub = rem_ch_sub.get(local, 0)
            ch_id = rem_chassis.get(local, b"")
            sysn = _fmt_lldp_id(ch_id, ch_sub) if ch_id else "?"
        pid_sub = rem_pid_sub.get(local, 0)
        pid_val = rem_pid.get(local, b"")
        pid_str = _fmt_lldp_id(pid_val, pid_sub) if pid_val is not None else "?"
        pdesc = rem_pdesc.get(local, "")
        extra = f" ({pdesc})" if pdesc else ""
        entry = f"{sysn} / {pid_str}{extra}"
        neighbors.setdefault(ifidx, []).append(entry)

    log.debug("LLDP ifindex neighbor entries: %d keys", len(neighbors))
    return neighbors

def gather_interface_rows(target, community, timeout, retries, pvid_map):
    log.debug("Gathering interface rows")
    names  = _walk_map_str(target, community, OID["ifName"],        timeout, retries)
    descrs = _walk_map_str(target, community, OID["ifDescr"],       timeout, retries)
    alias  = _walk_map_str(target, community, OID["ifAlias"],       timeout, retries)
    admin  = _walk_map_int(target, community, OID["ifAdminStatus"], timeout, retries)
    oper   = _walk_map_int(target, community, OID["ifOperStatus"],  timeout, retries)
    mtu    = _walk_map_int(target, community, OID["ifMtu"],         timeout, retries)
    hs     = _walk_map_int(target, community, OID["ifHighSpeed"],   timeout, retries)
    spd    = _walk_map_int(target, community, OID["ifSpeed"],       timeout, retries)
    mac    = _walk_map_octets(target, community, OID["ifPhysAddress"], timeout, retries)
    lastc  = _walk_map_int(target, community, OID["ifLastChange"],  timeout, retries)
    inerr  = _walk_map_int(target, community, OID["ifInErrors"],    timeout, retries)
    outerr = _walk_map_int(target, community, OID["ifOutErrors"],   timeout, retries)

    hc_in  = _walk_map_int(target, community, OID["ifHCInOctets"],  timeout, retries)
    hc_out = _walk_map_int(target, community, OID["ifHCOutOctets"], timeout, retries)
    in32   = _walk_map_int(target, community, OID["ifInOctets"],    timeout, retries)
    out32  = _walk_map_int(target, community, OID["ifOutOctets"],   timeout, retries)

    duplex = _walk_map_int(target, community, OID["dot3StatsDuplexStatus"], timeout, retries)

    sysuptime = snmp_get(target, community, OID["sysUpTime"], timeout, retries)
    sysuptime_ticks = int(sysuptime) if sysuptime is not None else None

    neigh = get_neighbors_by_ifindex(target, community, timeout, retries)

    rows = []
    all_ifidx = set().union(descrs, names, mtu, admin, oper)
    for idx in sorted(all_ifidx):
        nm = names.get(idx) or descrs.get(idx) or f"if{idx}"
        al = alias.get(idx, "")
        ad = {1: "up", 2: "down", 3: "testing"}.get(admin.get(idx, 0), "unknown")
        op = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(oper.get(idx, 0), "unknown")
        sp = _format_speed(hs.get(idx, 0), spd.get(idx, 0))
        du = _duplex_name(duplex.get(idx, 1))
        pv = pvid_map.get(idx)
        ib = hc_in.get(idx, None)
        ob = hc_out.get(idx, None)
        if ib is None:
            ib = in32.get(idx, 0)
        if ob is None:
            ob = out32.get(idx, 0)
        ie = inerr.get(idx, 0)
        oe = outerr.get(idx, 0)
        mc = _format_mac(mac.get(idx, b""))
        lc = _timeticks_to_age_str(lastc.get(idx), sysuptime_ticks)
        nb = ", ".join(neigh.get(idx, []))

        rows.append(InterfaceRow(
            idx, nm, al, ad, op, sp, mtu.get(idx, 0), du, pv,
            ib, ob, ie, oe, mc, lc, nb
        ))
    log.info("Assembled %d interface rows", len(rows))
    return rows
