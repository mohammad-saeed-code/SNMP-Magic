# discovery_entry.py
"""
Thin entry-point shim used by scan_api.py / job.py.

All real logic lives in snmp_magic/discovery.py.
This file exists only so scan_api.py can do:
    from discovery_entry import run as run_discovery
without needing to know the internal package layout.
"""

from snmp_magic.discovery import run, discover_cidr, ping_host, snmp_check, HostProbe

__all__ = ["run", "discover_cidr", "ping_host", "snmp_check", "HostProbe"]