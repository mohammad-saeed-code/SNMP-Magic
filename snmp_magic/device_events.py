# snmp_magic/device_events.py
"""
Change detection for network devices.

Every time a device is scanned, we compare the new state against the
previous scan and generate DeviceEvent rows for anything that changed.

Event kinds:
  device_new          first time this IP has ever been seen
  device_name_changed sysName changed between scans
  device_descr_changed sysDescr changed
  device_type_changed classified type changed
  snmp_lost           device was SNMP-reachable, now it isn't
  snmp_restored       SNMP reachable again
  interface_down      interface oper_status went down
  interface_up        interface came back up
  interface_new       new interface appeared
  interface_removed   interface disappeared
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlmodel import Field, Session, SQLModel, select
from sqlalchemy import Column, JSON

log = logging.getLogger(__name__)


# ── Model ─────────────────────────────────────────────────────────────────

class DeviceEvent(SQLModel, table=True):
    id:         Optional[int] = Field(default=None, primary_key=True)
    device_ip:  str
    kind:       str           # see module docstring
    ts:         datetime      = Field(default_factory=datetime.utcnow)
    detail:     Optional[Dict[str, Any]] = Field(
                    default=None, sa_column=Column(JSON)
                )


# ── Diff helpers ──────────────────────────────────────────────────────────

def _iface_key(iface: Dict) -> str:
    """Stable key for an interface across scans."""
    return str(iface.get("ifIndex") or iface.get("name") or "?")


def _iface_status(iface: Dict) -> str:
    return (iface.get("oper_status") or "unknown").lower()


def diff_device(
    ip:       str,
    prev:     Optional[Dict[str, Any]],   # previous scan payload (host dict)
    curr:     Dict[str, Any],             # current scan payload
    now:      datetime,
) -> List[DeviceEvent]:
    """
    Compare prev vs curr scan payloads and return list of DeviceEvent objects.
    Does NOT write to DB — caller does that.
    """
    events: List[DeviceEvent] = []

    def ev(kind: str, **detail):
        events.append(DeviceEvent(device_ip=ip, kind=kind, ts=now, detail=detail or None))

    # ── First ever scan ──────────────────────────────────────────────────
    if prev is None:
        ev("device_new",
           sys_name=curr.get("sys_name"),
           sys_descr=(curr.get("sys_descr") or "")[:120])
        return events   # no further diffs make sense for a new device

    # ── sysName change ───────────────────────────────────────────────────
    prev_name = (prev.get("sys_name") or "").strip()
    curr_name = (curr.get("sys_name") or "").strip()
    if prev_name and curr_name and prev_name != curr_name:
        ev("device_name_changed", old=prev_name, new=curr_name)

    # ── sysDescr change ──────────────────────────────────────────────────
    prev_descr = (prev.get("sys_descr") or "").strip()
    curr_descr = (curr.get("sys_descr") or "").strip()
    if prev_descr and curr_descr and prev_descr != curr_descr:
        ev("device_descr_changed",
           old=prev_descr[:120], new=curr_descr[:120])

    # ── SNMP reachability ────────────────────────────────────────────────
    prev_snmp = bool(prev.get("sys_name") or prev.get("interfaces"))
    curr_snmp = bool(curr.get("sys_name") or curr.get("interfaces"))
    if prev_snmp and not curr_snmp:
        ev("snmp_lost")
    elif not prev_snmp and curr_snmp:
        ev("snmp_restored", sys_name=curr_name)

    # ── Interface changes ────────────────────────────────────────────────
    prev_ifaces: Dict[str, Dict] = {
        _iface_key(i): i for i in (prev.get("interfaces") or [])
    }
    curr_ifaces: Dict[str, Dict] = {
        _iface_key(i): i for i in (curr.get("interfaces") or [])
    }

    all_keys = set(prev_ifaces) | set(curr_ifaces)
    for key in all_keys:
        p = prev_ifaces.get(key)
        c = curr_ifaces.get(key)

        if p is None and c is not None:
            ev("interface_new",
               name=c.get("name"), index=c.get("ifIndex"),
               status=_iface_status(c))

        elif p is not None and c is None:
            ev("interface_removed",
               name=p.get("name"), index=p.get("ifIndex"))

        else:
            # Both exist — check status change
            ps = _iface_status(p)
            cs = _iface_status(c)
            if ps != cs:
                if cs == "down":
                    ev("interface_down",
                       name=c.get("name"), index=c.get("ifIndex"),
                       old_status=ps, new_status=cs)
                elif cs == "up":
                    ev("interface_up",
                       name=c.get("name"), index=c.get("ifIndex"),
                       old_status=ps, new_status=cs)

    return events


# ── DB helpers ────────────────────────────────────────────────────────────

def record_events(s: Session, events: List[DeviceEvent]) -> None:
    """Bulk-insert events into the session (caller commits)."""
    for ev in events:
        s.add(ev)


def get_recent_events(
    s: Session,
    limit: int = 50,
    ip: Optional[str] = None,
    kinds: Optional[List[str]] = None,
) -> List[DeviceEvent]:
    stmt = select(DeviceEvent).order_by(DeviceEvent.ts.desc()).limit(limit)
    if ip:
        stmt = stmt.where(DeviceEvent.device_ip == ip)
    if kinds:
        stmt = stmt.where(DeviceEvent.kind.in_(kinds))
    return list(s.exec(stmt).all())


# ── Human-readable summaries ──────────────────────────────────────────────

_KIND_META: Dict[str, tuple] = {
    # kind              : (icon, template)
    "device_new":           ("🆕", "New device discovered"),
    "device_name_changed":  ("✏️",  "Name changed: {old} → {new}"),
    "device_descr_changed": ("📝", "Description updated"),
    "snmp_lost":            ("🔴", "SNMP stopped responding"),
    "snmp_restored":        ("🟢", "SNMP responding again"),
    "interface_down":       ("⬇️",  "Interface {name} went down"),
    "interface_up":         ("⬆️",  "Interface {name} came back up"),
    "interface_new":        ("➕", "New interface: {name}"),
    "interface_removed":    ("➖", "Interface removed: {name}"),
}


def event_summary(ev: DeviceEvent) -> Dict[str, str]:
    """Return {icon, text, severity} for display."""
    meta = _KIND_META.get(ev.kind, ("❓", ev.kind))
    icon, tmpl = meta
    detail = ev.detail or {}
    try:
        text = tmpl.format(**detail)
    except (KeyError, AttributeError):
        text = tmpl

    severity = "info"
    if ev.kind in ("snmp_lost", "interface_down", "interface_removed"):
        severity = "warn"
    elif ev.kind in ("device_new", "snmp_restored", "interface_up"):
        severity = "ok"

    return {"icon": icon, "text": text, "severity": severity}