#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
from typing import Any, Dict, List, Optional
from ipaddress import ip_address

from .snmpio import transport
from .device import get_device_header
from .vlan import get_vlan_views, get_pvid_map
from .lldp import get_lldp_neighbors
from .ifmaps import build_ifindex_maps
from .interfaces import gather_interface_rows
from .print_table import (
    print_vlan_table,
    print_lldp_neighbors,
    print_pvids,
    print_interfaces_table,
    print_discovery_list,
)
from .discovery import discover_cidr
from .mac import get_fdb_entries


def _serialize_host_result(
    host: str,
    sys_name: Optional[str],
    sys_descr: Optional[str],
    vlans,
    pvid_map: Dict[int, int],
    interfaces,
    lldp,
    endpoints: Optional[list] = None,          # NEW
) -> Dict[str, Any]:
    return {
        "target": host,
        "sys_name": sys_name,
        "sys_descr": sys_descr,
        "vlans": [
            {
                "vid": v.vid,
                "name": v.name,
                "untagged": list(v.untagged or []),
                "tagged": list(v.tagged or []),
            }
            for v in (vlans or [])
        ],
        "pvid_map": pvid_map or {},
        "interfaces": [
            {
                "ifIndex": r.ifIndex,
                "name": r.name,
                "alias": r.alias,
                "admin": r.admin,
                "oper": r.oper,
                "speed": r.speed,
                "mtu": r.mtu,
                "duplex": r.duplex,
                "pvid": r.pvid,
                "in_bytes": r.in_bytes,
                "out_bytes": r.out_bytes,
                "in_err": r.in_err,
                "out_err": r.out_err,
                "mac": r.mac,
                "last_change": r.last_change,
                "neighbors": r.neighbors,
            }
            for r in (interfaces or [])
        ],
        "lldp_neighbors": lldp or {},
        "endpoints": endpoints or [],           # NEW
    }



def scan_single_host(
    host: str,
    auth,
    port: int,
    timeout: int,
    retries: int,
    max_ports: int,
    vlan_ports_mode: str,
    collect: bool = False,
) -> Optional[Dict[str, Any]]:
    # Validate IP best-effort (hostnames are allowed)
    try:
        ip_address(host)
    except ValueError:
        pass

    tgt = transport(host, port, timeout, retries)

    # --- Try v2c first, then fallback to v1 (same community) if needed ---
    auth_used = auth
    sys_name, sys_descr = get_device_header(tgt, auth_used, timeout, retries)
    if not sys_name and isinstance(auth_used, tuple):
        ver, comm = auth_used
        if str(ver).lower() == "2c":
            # fallback to v1
            v1_auth = ("1", comm)
            sys_name_v1, sys_descr_v1 = get_device_header(tgt, v1_auth, timeout, retries)
            if sys_name_v1:
                auth_used = v1_auth
                sys_name, sys_descr = sys_name_v1, sys_descr_v1

    # Header (don’t leak secrets)
    if isinstance(auth_used, dict):
        user = auth_used.get("user", "")
        ap = (auth_used.get("auth_proto") or "NONE").upper()
        pp = (auth_used.get("priv_proto") or "NONE").upper()
        auth_hdr = f"v3 user='{user}' auth={ap} priv={pp}"
    elif isinstance(auth_used, tuple):
        ver, comm = auth_used
        auth_hdr = f"v{ver} community='{comm}'"
    else:
        auth_hdr = f"v2c community='{auth_used}'"

    # When printing (table mode), show a banner. In collect mode, stay silent.
    if not collect:
        print(f"\n=== Scanning {host}  {auth_hdr}  port: {port} ===")

    # Build labels for PVID printing
    _, if_labels = build_ifindex_maps(tgt, auth_used, timeout, retries)

    # VLANs (vendor first, standard fallback)
    vlans = get_vlan_views(
        tgt,
        auth_used,
        timeout,
        retries,
        max_ports=max_ports,
        return_numeric=(vlan_ports_mode == "numeric"),
    )

    # PVIDs
    pvid_map = get_pvid_map(tgt, auth_used, timeout, retries)

    # Interfaces (per-port summary incl. VLAN=PVID and LLDP neighbors)
    vlan_names = {v.vid: v.name for v in vlans} if vlans else {}
    rows = gather_interface_rows(tgt, auth_used, timeout, retries, pvid_map)

    # LLDP summary by local-if label
    lldp = get_lldp_neighbors(tgt, auth_used, timeout, retries)

    # --- FDB (MAC table) + OUI enrichment ---
    try:
        fdb = get_fdb_entries(tgt, auth_used, timeout, retries, include_non_dynamic=False)
        endpoints = [
            {
                "mac": e.mac,
                "ifIndex": e.ifIndex,
                "vlan": e.vlan,
                "status": e.status,
                "vendor": e.vendor,
            }
            for e in fdb
        ]
    except Exception:
        endpoints = []

    if collect:
        return _serialize_host_result(
            host, sys_name, sys_descr, vlans, pvid_map, rows, lldp,
            endpoints=endpoints,
        )

    # ---- table-printing path (existing behavior) ----
    if sys_name:
        print(f"Device: {sys_name}")
    if sys_descr:
        print(f"Descr : {sys_descr}\n")

    if vlans:
        print_vlan_table(vlans)
    else:
        print("No VLAN data found via vendor or Q-BRIDGE.\n")

    print_pvids(pvid_map, if_labels)
    print_interfaces_table(rows, vlan_names=vlan_names, max_name=24, max_alias=24, max_neighbor=50)
    print_lldp_neighbors(lldp)
    return None



def main():
    ap = argparse.ArgumentParser(description="SNMP L2/LLDP/VLAN scanner (with discovery)")

    # Target & common options
    ap.add_argument("target", nargs="?", help="Target IP / hostname (omit when using --discover)")
    ap.add_argument("-c", "--community", default="public", help="SNMP community (v1/v2c)")
    ap.add_argument("-p", "--port", type=int, default=161, help="SNMP port")
    ap.add_argument("--timeout", type=int, default=2, help="SNMP request timeout (s)")
    ap.add_argument("--retries", type=int, default=2, help="SNMP retries")
    ap.add_argument("--max-ports", type=int, default=52, help="Hint for vendor PortList width")
    ap.add_argument(
        "--vlan-ports",
        choices=["label", "numeric"],
        default="label",
        help="Show VLAN membership using interface labels or numeric ports (vendor tables only)",
    )

    # SNMP version selection
    ap.add_argument("--snmp-version", choices=["1", "2c", "3"], default="2c",
                    help="SNMP protocol version (default: 2c)")

    # SNMPv3 options (active when --snmp-version 3)
    ap.add_argument("--v3-user", help="SNMPv3 username (required when --snmp-version 3)")
    ap.add_argument("--v3-auth-key", help="SNMPv3 auth key/passphrase")
    ap.add_argument("--v3-priv-key", help="SNMPv3 privacy key/passphrase")
    ap.add_argument("--v3-auth-proto", choices=["MD5", "SHA", "NONE"], default="SHA", help="SNMPv3 auth protocol")
    ap.add_argument("--v3-priv-proto", choices=["AES", "DES", "NONE"], default="AES", help="SNMPv3 privacy protocol")

    # Discovery options
    ap.add_argument("--discover", metavar="CIDR", help="Ping+SNMP discover a CIDR (e.g., 192.168.81.0/24)")
    ap.add_argument("--yes", action="store_true", help="Do not prompt after discovery; start scanning immediately")
    ap.add_argument("--workers", type=int, default=128, help="Max parallel discovery probes (default: 128)")

    # Output options
    ap.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    ap.add_argument("--out", help="Write output to file (json). Defaults to stdout if omitted.")

    args = ap.parse_args()

    # Validate v3
    if args.snmp_version == "3" and not args.v3_user:
        ap.error("--snmp-version 3 requires --v3-user")

    # Build auth object: v1/v2c as tuple or v3 as dict
    if args.snmp_version == "3":
        auth = {
            "user": args.v3_user,
            "auth_key": args.v3_auth_key,
            "priv_key": args.v3_priv_key,
            "auth_proto": args.v3_auth_proto,
            "priv_proto": args.v3_priv_proto,
        }
    else:
        # v1 or v2c
        auth = (args.snmp_version, args.community)

    # Discovery mode
    if args.discover:
        print(f"Starting discovery on {args.discover} (port={args.port}) ...")
        probes = discover_cidr(
            args.discover,
            auth,
            args.port,
            args.timeout,
            args.retries,
            ping_timeout_ms=600,
            workers=args.workers,
        )

        if args.format == "table":
            print_discovery_list(probes)

        # Filter to hosts that responded to ping AND SNMP
        scan_list = [p.ip for p in probes if p.ping_ok and p.snmp_ok]
        if not scan_list:
            if args.format == "json":
                payload = {"mode": "discovery", "cidr": args.discover, "hosts": [], "probes": [
                    {"ip": p.ip, "ping_ok": p.ping_ok, "snmp_ok": p.snmp_ok, "sys_name": p.sys_name, "sys_descr": p.sys_descr}
                    for p in probes
                ]}
                out = json.dumps(payload, indent=2)
                if args.out:
                    with open(args.out, "w", encoding="utf-8") as f:
                        f.write(out)
                else:
                    print(out)
            else:
                print("No SNMP-capable hosts found. Exiting.")
            return

        # Ask user to proceed unless --yes (table mode only; for json we proceed automatically)
        if args.format == "table" and not args.yes:
            try:
                answer = input(f"Scan these {len(scan_list)} host(s) now? [y/N]: ").strip().lower()
            except EOFError:
                answer = "n"
            if answer not in ("y", "yes"):
                print("Aborted by user.")
                return

        if args.format == "json":
            collected: List[Dict[str, Any]] = []
            for ip in scan_list:
                data = scan_single_host(
                    ip,
                    auth,
                    args.port,
                    args.timeout,
                    args.retries,
                    args.max_ports,
                    args.vlan_ports,
                    collect=True,
                )
                collected.append(data or {})
            payload = {
                "mode": "discovery",
                "cidr": args.discover,
                "hosts": collected,
                "probes": [
                    {
                        "ip": p.ip,
                        "ping_ok": p.ping_ok,
                        "snmp_ok": p.snmp_ok,
                        "sys_name": p.sys_name,
                        "sys_descr": p.sys_descr,
                    }
                    for p in probes
                ],
            }
            out = json.dumps(payload, indent=2)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(out)
            else:
                print(out)
            return

        # table mode scan
        for ip in scan_list:
            scan_single_host(
                ip,
                auth,
                args.port,
                args.timeout,
                args.retries,
                args.max_ports,
                args.vlan_ports,
                collect=False,
            )
        return

    # Single target mode (original behavior)
    if not args.target:
        ap.error("You must provide a target IP/hostname or use --discover CIDR")

    if args.format == "json":
        data = scan_single_host(
            args.target,
            auth,
            args.port,
            args.timeout,
            args.retries,
            args.max_ports,
            args.vlan_ports,
            collect=True,
        )
        out = json.dumps({"mode": "single", "host": data}, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)
        return

    # table mode
    scan_single_host(
        args.target,
        auth,
        args.port,
        args.timeout,
        args.retries,
        args.max_ports,
        args.vlan_ports,
        collect=False,
    )


if __name__ == "__main__":
    main()
