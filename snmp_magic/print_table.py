# snmp_magic/print_table.py

# ---------- helpers ----------
def _fmt_bytes(n):
    try:
        n = int(n)
    except Exception:
        return str(n)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.1f} {units[i]}" if i else f"{int(f)} {units[i]}"

def _truncate(s, maxlen):
    s = s or ""
    return s if len(s) <= maxlen else (s[: maxlen - 1] + "…")

def _short_list(items, max_items=8):
    """Return 'a,b,c +N more' for long lists; '-' for empty."""
    items = list(items or [])
    if not items:
        return "-"
    if len(items) <= max_items:
        return ",".join(items)
    head = ",".join(items[:max_items])
    return f"{head} +{len(items) - max_items} more"


# ---------- VLANs ----------
def print_vlan_table(views, label_mode=None):
    if not views:
        print("No VLAN data.")
        return
    print("VLANs")
    print("=====")
    print("VID | Name                | Untagged (count)                 | Tagged (count)")
    print("----+---------------------+----------------------------------+------------------------------")
    for v in sorted(views, key=lambda x: x.vid):
        unt = _short_list(v.untagged, max_items=8)
        tag = _short_list(v.tagged, max_items=8)
        unt_cnt = 0 if v.untagged is None else len(v.untagged)
        tag_cnt = 0 if v.tagged is None else len(v.tagged)
        print(f"{v.vid:>4} | {v.name:<19} | {unt:<32} ({unt_cnt:>3}) | {tag:<28} ({tag_cnt:>3})")
    print()


# ---------- PVIDs ----------
def print_pvids(pvid_map, if_labels):
    if not pvid_map:
        return
    print("Per-port PVID")
    print("=============")
    print("IfName/Descr           | ifIndex | PVID")
    print("-----------------------+---------+-----")
    for ifidx in sorted(pvid_map):
        name = if_labels.get(ifidx, f"if{ifidx}")
        print(f"{name:<23} | {ifidx:>7} | {pvid_map[ifidx]}")
    print()


# ---------- Interfaces ----------
def print_interfaces_table(rows, vlan_names=None, max_name=24, max_alias=24, max_neighbor=50):
    if not rows:
        print("No interface data.")
        return
    print("Interfaces")
    print("==========")
    header = ("Idx | Name | Alias | Admin/Oper | Speed | MTU | Duplex | VLAN | "
              "InBytes | OutBytes | InErr | OutErr | MAC | Last Change | Neighbor(s)")
    print(header)
    print("-" * len(header))
    for r in rows:
        name = _truncate(r.name, max_name)
        alias = _truncate(r.alias or "", max_alias)
        # VLAN as "VID (Name)" when available
        if r.pvid is None:
            vlan_disp = ""
        else:
            if vlan_names and r.pvid in vlan_names:
                vlan_disp = f"{r.pvid} ({vlan_names[r.pvid]})"
            else:
                vlan_disp = f"{r.pvid}"
        nb = _truncate(r.neighbors or "", max_neighbor)
        print(
            f"{r.ifIndex:>3} | {name} | {alias} | {r.admin}/{r.oper} | {r.speed} | "
            f"{r.mtu} | {r.duplex} | {vlan_disp} | "
            f"{_fmt_bytes(r.in_bytes)} | {_fmt_bytes(r.out_bytes)} | "
            f"{r.in_err} | {r.out_err} | {r.mac} | {r.last_change} | {nb}"
        )
    print()


# ---------- LLDP summary (optional) ----------
def print_lldp_neighbors(lldp):
    if not lldp:
        print("No LLDP neighbors found.")
        return
    print("LLDP neighbors")
    print("==============")
    for local_if, peers in lldp.items():
        for peer in peers:
            sysn = peer.get("sysName", "?")
            pid = peer.get("portId", "?")
            desc = peer.get("portDesc", "")
            extra = f" ({desc})" if desc else ""
            print(f" - {local_if} -> {sysn} / {pid}{extra}")


# ---------- Discovery results ----------
def print_discovery_list(probes):
    if not probes:
        print("No responsive hosts found in discovery.")
        return
    print("Discovery results")
    print("=================")
    print("IP Address        | Ping | SNMP | sysName")
    print("------------------+------+------ +---------------------------")
    for p in probes:
        sysn = p.sys_name or "-"
        print(f"{p.ip:<18} | {'ok' if p.ping_ok else 'no':<4} | {'ok' if p.snmp_ok else 'no':<4} | {sysn}")
    print()
