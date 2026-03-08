# map_api.py
"""
Topology map API routes.

Endpoints:
  POST /api/map/scan          start a background map scan, returns job_id
  GET  /api/map/scan/{id}/status   poll job progress
  GET  /api/map/snapshot      load last persisted map from DB
  GET  /ui/map                serve the map HTML page
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from snmp_magic.auth import require_user
from snmp_magic.ui_env import templates

log = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helper: load DB devices for enrichment
# ---------------------------------------------------------------------------

def _load_db_devices() -> Dict[str, Dict]:
    """Return {ip: {sys_name, sys_descr, mac}} from Device + Interface tables."""
    try:
        from snmp_magic.store import engine, Device, Interface
        from sqlmodel import Session, select

        result: Dict[str, Dict] = {}
        with Session(engine) as s:
            devs = s.exec(select(Device)).all()
            for d in devs:
                result[d.ip] = {
                    "sys_name":  d.sys_name,
                    "sys_descr": d.sys_descr,
                    "mac":       None,
                }
            # Grab first MAC per device from interfaces
            ifaces = s.exec(select(Interface)).all()
            mac_by_device: Dict[int, str] = {}
            for iface in ifaces:
                if iface.mac_address and iface.device_id not in mac_by_device:
                    mac_by_device[iface.device_id] = iface.mac_address

            # Map device_id → ip then attach mac
            dev_id_to_ip = {d.id: d.ip for d in devs}
            for dev_id, mac in mac_by_device.items():
                ip = dev_id_to_ip.get(dev_id)
                if ip and ip in result:
                    result[ip]["mac"] = mac

        return result
    except Exception as exc:
        log.warning("Could not load DB devices for map enrichment: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _save_snapshot(payload: Dict[str, Any]) -> None:
    """Store map snapshot in the Scan table (mode='map')."""
    try:
        from snmp_magic.store import save_scan
        save_scan(payload, mode="map", target=payload.get("cidr", ""), status="ok")
    except Exception as exc:
        log.error("Failed to save map snapshot: %s", exc)


def _load_snapshot() -> Optional[Dict[str, Any]]:
    """Load the most recent map snapshot from DB."""
    try:
        from snmp_magic.store import engine, Scan
        from sqlmodel import Session, select

        with Session(engine) as s:
            snap = s.exec(
                select(Scan)
                .where(Scan.mode == "map")
                .order_by(Scan.id.desc())
                .limit(1)
            ).first()
            if snap and snap.result:
                return snap.result
    except Exception as exc:
        log.warning("Could not load map snapshot: %s", exc)
    return None


# ---------------------------------------------------------------------------
# Background job runner
# ---------------------------------------------------------------------------

def _run_map_scan(params: Dict[str, Any], progress=lambda *a, **k: None):
    """Entry point for job.py start_job()."""
    from snmp_magic.map_scan import build_topology

    cidr = params.get("cidr", "").strip()
    if not cidr:
        raise ValueError("No CIDR provided")

    max_hops       = int(params.get("max_hops", 20))
    ping_timeout   = int(params.get("ping_timeout_ms", 800))

    db_devices = _load_db_devices()

    def _cb(pct: int, msg: str):
        progress(pct, status=msg)

    result = build_topology(
        cidr,
        ping_timeout_ms=ping_timeout,
        max_hops=max_hops,
        progress_cb=_cb,
        db_devices=db_devices,
    )

    _save_snapshot(result)
    return result


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/api/map/scan", dependencies=[Depends(require_user)])
async def start_map_scan(request: Request):
    """Start a background topology scan. Returns {job_id}."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    cidr = body.get("cidr", "").strip()
    if not cidr:
        return JSONResponse({"error": "cidr required"}, status_code=400)

    try:
        from job import start_job
        job_id = start_job(_run_map_scan, kwargs={"params": body})
        return {"job_id": job_id}
    except Exception as exc:
        log.error("Failed to start map scan job: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/map/scan/{job_id}/status", dependencies=[Depends(require_user)])
def map_scan_status(job_id: str):
    """Poll job progress."""
    try:
        from job import get_status
        return get_status(job_id)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/map/snapshot", dependencies=[Depends(require_user)])
def get_map_snapshot():
    """Return last persisted map snapshot, or empty graph."""
    snap = _load_snapshot()
    if snap:
        return snap
    return {"nodes": [], "edges": [], "stats": {}, "scanned_at": None}


@router.get("/ui/map", response_class=HTMLResponse, dependencies=[Depends(require_user)])
def map_page(request: Request):
    return templates.TemplateResponse(
        "map.html", {"request": request, "active": "map"}
    )