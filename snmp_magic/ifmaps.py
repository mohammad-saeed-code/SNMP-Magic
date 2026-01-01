from collections import defaultdict
import logging
from .mibs import OID
from .snmpio import snmp_walk

log = logging.getLogger(__name__)

def build_ifindex_maps(target, community, timeout, retries):
    log.debug("Building ifIndex maps (ifName/ifDescr and bridgePort→ifIndex)")
    # ifIndex -> ifName/ifDescr
    if_names = {}
    for oid, val in snmp_walk(target, community, OID["ifName"], timeout, retries):
        if_index = int(oid.split('.')[-1])
        if_names[if_index] = str(val)

    if_descr = {}
    for oid, val in snmp_walk(target, community, OID["ifDescr"], timeout, retries):
        if_index = int(oid.split('.')[-1])
        if_descr[if_index] = str(val)

    # bridgePort -> ifIndex
    bridge_to_if = {}
    for oid, val in snmp_walk(target, community, OID["dot1dBasePortIfIndex"], timeout, retries):
        bridge_port = int(oid.split('.')[-1])
        bridge_to_if[bridge_port] = int(val)

    # Friendly ifName fallback to ifDescr or ifIndex
    if_label = defaultdict(str)
    for ifidx in set(list(if_names.keys()) + list(if_descr.keys())):
        if_label[ifidx] = if_names.get(ifidx) or if_descr.get(ifidx) or f"if{ifidx}"

    log.debug("ifIndex labels=%d bridgePorts=%d", len(if_label), len(bridge_to_if))
    return bridge_to_if, dict(if_label)
