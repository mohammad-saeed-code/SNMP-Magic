# events_api.py
"""
Events / change-detection API routes.

GET /api/events              recent events across all devices (feed)
GET /api/events/{ip}         events for a specific device
GET /api/devices/{ip}/type   classification for a single device
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from snmp_magic.auth import require_user
from snmp_magic.store import engine, Device
from snmp_magic.device_events import DeviceEvent, get_recent_events, event_summary
from snmp_magic.device_classify import classify

router = APIRouter()


@router.get("/api/events", dependencies=[Depends(require_user)])
def list_events(
    limit: int = Query(50, ge=1, le=200),
    ip: Optional[str] = Query(None),
    kind: Optional[str] = Query(None),
):
    kinds = [kind] if kind else None
    with Session(engine) as s:
        events = get_recent_events(s, limit=limit, ip=ip, kinds=kinds)
        return [
            {
                "id":        ev.id,
                "ip":        ev.device_ip,
                "kind":      ev.kind,
                "ts":        ev.ts.isoformat(),
                "detail":    ev.detail,
                **event_summary(ev),
            }
            for ev in events
        ]


@router.get("/api/events/{ip}", dependencies=[Depends(require_user)])
def device_events(ip: str, limit: int = Query(30, ge=1, le=100)):
    with Session(engine) as s:
        events = get_recent_events(s, limit=limit, ip=ip)
        return [
            {
                "id":     ev.id,
                "kind":   ev.kind,
                "ts":     ev.ts.isoformat(),
                "detail": ev.detail,
                **event_summary(ev),
            }
            for ev in events
        ]


@router.get("/api/devices/{ip}/classify", dependencies=[Depends(require_user)])
def classify_device(ip: str):
    """Return current classification for a device."""
    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            from fastapi import HTTPException
            raise HTTPException(404, f"No device {ip}")
        cls = classify(sys_descr=dev.sys_descr, sys_name=dev.sys_name)
        return {
            "ip":          ip,
            "device_type": cls.device_type,
            "label":       cls.label,
            "icon":        cls.icon,
        }