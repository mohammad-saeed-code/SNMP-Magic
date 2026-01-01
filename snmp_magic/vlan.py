# snmp_magic/vlan.py
from collections import namedtuple
import logging
from .mibs import OID
from .snmpio import snmp_walk, snmp_get
from .ifmaps import build_ifindex_maps
from .vendor.dlink import get_vendor_vlan_views, get_vendor_pvid_map
from .probe import probe_log

log = logging.getLogger(__name__)

VlanView = namedtuple("VlanView", "vid name tagged untagged")

def decode_bitmap_msb(octets) -> set:
    if octets is None:
        return set()
    if isinstance(octets, bytes):
        data = octets
    else:
        try:
            data = bytes(octets)
        except Exception:
            data = bytes(str(octets), 'latin-1', errors='ignore')

    ports = set()
    bit_index = 1
    for b in data:
        for bit in range(8):
            if b & (1 << (7 - bit)):
                ports.add(bit_index)
            bit_index += 1
    return ports

def _standard_vlan_views(target, community, timeout, retries, bridge_to_if, if_labels):
    log.debug("Building standard Q-BRIDGE VLAN views")
    vlan_names = {}
    for oid, val in snmp_walk(target, community, OID["dot1qVlanStaticName"], timeout, retries):
        vid = int(oid.split('.')[-1])
        vlan_names[vid] = str(val) if str(val) else f"VLAN-{vid}"

    static_eg = {}
    for oid, val in snmp_walk(target, community, OID["dot1qVlanStaticEgressPorts"], timeout, retries):
        vid = int(oid.split('.')[-1])
        static_eg[vid] = decode_bitmap_msb(val)

    static_unt = {}
    for oid, val in snmp_walk(target, community, OID["dot1qVlanStaticUntaggedPorts"], timeout, retries):
        vid = int(oid.split('.')[-1])
        static_unt[vid] = decode_bitmap_msb(val)

    current_eg = {}
    for oid, val in snmp_walk(target, community, OID["dot1qVlanCurrentEgressPorts"], timeout, retries):
        vid = int(oid.split('.')[-1])
        current_eg[vid] = decode_bitmap_msb(val)

    pvid_by_bridge = {}
    for oid, val in snmp_walk(target, community, OID["dot1qPvid"], timeout, retries):
        bridge_port = int(oid.split('.')[-1])
        pvid_by_bridge[bridge_port] = int(val)

    vids = set(vlan_names) | set(static_eg) | set(static_unt) | set(current_eg) | set(pvid_by_bridge.values())
    views = []

    def bp_to_iflabels(bp_set: set):
        labels = []
        for bp in sorted(bp_set):
            ifidx = bridge_to_if.get(bp)
            if not ifidx:
                continue
            labels.append(if_labels.get(ifidx, f"if{ifidx}"))
        return labels

    for vid in sorted(vids):
        name = vlan_names.get(vid, f"VLAN-{vid}")
        tagged_bp = static_eg.get(vid) or current_eg.get(vid) or set()
        untagged_bp = static_unt.get(vid, set())
        pvid_ports = {bp for bp, pv in pvid_by_bridge.items() if pv == vid}
        if not untagged_bp and pvid_ports:
            untagged_bp = pvid_ports - tagged_bp

        views.append(VlanView(
            vid=vid,
            name=name,
            tagged=bp_to_iflabels(tagged_bp),
            untagged=bp_to_iflabels(untagged_bp),
        ))
    log.info("Standard VLAN views built: %d VLANs", len(views))
    return views

def get_vlan_views(target, community, timeout, retries, max_ports=None, return_numeric: bool = False):
    bridge_to_if, if_labels = build_ifindex_maps(target, community, timeout, retries)

    vendor_views = get_vendor_vlan_views(target, community, timeout, retries, max_ports=max_ports)
    if vendor_views:
        log.info("Using vendor VLAN tables: %d VLANs", len(vendor_views))

        def port_to_label(p):
            ifidx = bridge_to_if.get(p)
            return if_labels.get(ifidx, f"port{p}") if ifidx else f"port{p}"

        views = []
        for vv in vendor_views:
            egr = vv.egress_ports or set()
            unt = vv.untagged_ports or set()
            tagged_only = egr - unt if egr else set()

            if return_numeric:
                tagged = [str(p) for p in sorted(tagged_only)]
                untagged = [str(p) for p in sorted(unt)]
            else:
                tagged = [port_to_label(p) for p in sorted(tagged_only)]
                untagged = [port_to_label(p) for p in sorted(unt)]

            views.append(VlanView(vid=vv.vid, name=vv.name, tagged=tagged, untagged=untagged))
        return views

    # Vendor empty → log fallback to Q-BRIDGE in the probe file (if enabled)
    try:
        soid = snmp_get(target, community, OID["sysObjectID"], timeout, retries)
    except Exception:
        soid = None
    probe_log({
        "phase": "vlan",
        "outcome": "fallback",
        "target": str(target),
        "sysObjectID": str(soid) if soid is not None else None,
        "reason": "vendor_empty",
    })

    log.info("Vendor VLAN tables empty; falling back to Q-BRIDGE")
    views = _standard_vlan_views(target, community, timeout, retries, bridge_to_if, if_labels)

    # If Q-BRIDGE also produced nothing, note it for later analysis
    if not views:
        probe_log({
            "phase": "vlan",
            "outcome": "novlan",
            "target": str(target),
            "sysObjectID": str(soid) if soid is not None else None,
            "reason": "vendor_and_qbridge_empty",
        })

    return views

def get_pvid_map(target, community, timeout, retries):
    vendor = get_vendor_pvid_map(target, community, timeout, retries)
    if vendor:
        log.info("Using vendor PVID map entries=%d", len(vendor))
        return vendor

    # Vendor PVID empty → log fallback to standard
    try:
        soid = snmp_get(target, community, OID["sysObjectID"], timeout, retries)
    except Exception:
        soid = None
    probe_log({
        "phase": "pvid",
        "outcome": "fallback",
        "target": str(target),
        "sysObjectID": str(soid) if soid is not None else None,
        "reason": "vendor_empty",
    })

    bridge_to_if, _ = build_ifindex_maps(target, community, timeout, retries)
    pvids = {}
    for oid, val in snmp_walk(target, community, OID["dot1qPvid"], timeout, retries):
        bridge_port = int(oid.split('.')[-1])
        vid = int(val)
        ifidx = bridge_to_if.get(bridge_port)
        if ifidx:
            pvids[ifidx] = vid
    log.info("Standard PVID map entries=%d", len(pvids))

    if not pvids:
        probe_log({
            "phase": "pvid",
            "outcome": "nopvid",
            "target": str(target),
            "sysObjectID": str(soid) if soid is not None else None,
            "reason": "vendor_and_standard_empty",
        })

    return pvids

# Back-compat for tests expecting decode_bitmap
def decode_bitmap(octets) -> set:
    return decode_bitmap_msb(octets)
