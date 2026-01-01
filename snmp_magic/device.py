from .mibs import OID
from .snmpio import snmp_get
import logging

log = logging.getLogger(__name__)

def get_device_header(target, community, timeout, retries):
    log.debug("Fetching device header (sysName/sysDescr)")
    sys_name = snmp_get(target, community, OID["sysName"], timeout, retries)
    sys_descr = snmp_get(target, community, OID["sysDescr"], timeout, retries)
    return (str(sys_name) if sys_name else None, str(sys_descr) if sys_descr else None)
