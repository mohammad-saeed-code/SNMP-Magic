# server.py
from typing import Optional, Dict, Any, List, Iterable
from datetime import datetime
import os
import time
import io
import asyncio
import anyio
import logging
from pathlib import Path
from threading import Lock
from dataclasses import dataclass, field
import functools
import sys
from fastapi import FastAPI, HTTPException, Query, Request, Path as FPath, Depends, Header
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import pandas as pd
from sqlmodel import Session, select
from sqlalchemy import func
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from fastapi.responses import RedirectResponse, Response
from snmp_magic.store import init_db, save_scan, engine, Device, Scan
from snmp_magic.snmpio import transport, snmp_get
from snmp_magic.device import get_device_header
from snmp_magic.vlan import get_vlan_views, get_pvid_map
from snmp_magic.lldp import get_lldp_neighbors
from snmp_magic.ifmaps import build_ifindex_maps
from snmp_magic.interfaces import gather_interface_rows
from snmp_magic.discovery import discover_cidr, ping_host
from snmp_magic.mac import get_fdb_entries
from snmp_magic.mibs import OID
from snmp_magic.logging_setup import setup_logging, attach_ui_log_buffer, get_ui_logs_from
from snmp_magic.routes_auth import router as auth_router
from snmp_magic.auth import require_user, require_admin
from pathlib import Path
from fastapi.staticfiles import StaticFiles

from snmp_magic.ui_env import BASE_DIR, templates

from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from snmp_magic.store import verify_user_password, issue_token

# scan_api.py (FastAPI)
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
import time
from snmp_magic.note_api import router as device_notes_router


# server.py (FastAPI app)
from fastapi import FastAPI
from scan_api import router as scan_router
from schedule_api import router as schedule_router
from snmp_magic.routes_settings import router as settings_router

app = FastAPI()
app = FastAPI(title="snmp-magic API")
app.include_router(scan_router)
router = APIRouter()
app.include_router(schedule_router) 
app.include_router(auth_router)
app.include_router(settings_router)
app.include_router(device_notes_router)


AUTH_COOKIE = os.getenv("AUTH_COOKIE", "snmp_magic_token")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"   # set 1 behind HTTPS
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")    # lax is good for normal sites

def app_base_dir() -> Path:
    # PyInstaller onefile
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]

    # PyInstaller onedir: data is in "<exe_dir>/_internal"
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        internal = exe_dir / "_internal"
        if internal.is_dir():
            return internal
        return exe_dir

    # Normal Python run: folder containing this file
    return Path(__file__).resolve().parent

# -----------------------------------------------------------------------------
# Scan job manager (global)
# -----------------------------------------------------------------------------
@dataclass
class ScanJob:
    key: str
    started_at: float = field(default_factory=time.time)
    cancel: bool = False

class ScanManager:
    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}
        self._lock = Lock()
    def start(self, key: str) -> ScanJob:
        with self._lock:
            job = ScanJob(key=key)
            self._jobs[key] = job
            return job
    def get(self, key: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(key)
    def stop(self, key: str) -> None:
        with self._lock:
            if key in self._jobs:
                self._jobs[key].cancel = True
    def clear(self, key: str) -> None:
        with self._lock:
            self._jobs.pop(key, None)
    def list_keys(self) -> List[str]:
        with self._lock:
            return list(self._jobs.keys())

SCAN: ScanManager = ScanManager()

def _cancelled(job_key: str) -> bool:
    j = SCAN.get(job_key)
    return bool(j and j.cancel)

# -----------------------------------------------------------------------------
# App + config
# -----------------------------------------------------------------------------
log = logging.getLogger(__name__)
OUI_DB_PATH = os.getenv("OUI_DB_PATH")  # path to full OUI DB (CSV/flat)


# --- Security knobs (env-overridable) ---
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "1") == "1"
API_KEY = os.getenv("API_KEY", "P@sSvv0RdSupers3kret!1@2#")

def require_api_key(x_api_key: str = Header(None)):
    if not REQUIRE_API_KEY:
        return
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(401, "Unauthorized")

# --- Basic per-client rate limits for scan endpoints ---
SCAN_LIMIT = int(os.getenv("SCAN_LIMIT", "10"))      # max requests
SCAN_WINDOW = int(os.getenv("SCAN_WINDOW", "60"))    # seconds
_rate: dict[str, list[float]] = {}

def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    hits = [t for t in _rate.get(ip, []) if now - t < SCAN_WINDOW]
    if len(hits) >= SCAN_LIMIT:
        raise HTTPException(429, "Too many scan requests; slow down.")
    hits.append(now)
    _rate[ip] = hits

def rate_limiter_dep(request: Request):
    rate_limit(request)

# ---------- Static & Templates ----------
BASE_DIR = app_base_dir()

# Templates directory
templates_dir_env = os.getenv("TEMPLATES_DIR")
templates_dir = Path(templates_dir_env) if templates_dir_env else (BASE_DIR / "templates")
templates_dir = templates_dir.resolve()

# Static directory
static_dir_env = os.getenv("STATIC_DIR")
static_dir = Path(static_dir_env) if static_dir_env else (BASE_DIR / "static")
static_dir = static_dir.resolve()

if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")



# ---------- Request models ----------
from pydantic import BaseModel

class SNMPv12c(BaseModel):
    version: str = "2c"           # "1" or "2c"
    community: str = "public"

class SNMPv3(BaseModel):
    version: str = "3"
    user: str
    auth_key: Optional[str] = None
    priv_key: Optional[str] = None
    auth_proto: str = "SHA"       # MD5|SHA|NONE
    priv_proto: str = "AES"       # AES|DES|NONE

class ScanHostReq(BaseModel):
    target: str
    port: int = 161
    timeout: int = 2
    retries: int = 2
    max_ports: int = 52
    vlan_ports: str = "label"     # label|numeric
    snmp_v12c: Optional[SNMPv12c] = None
    snmp_v3: Optional[SNMPv3] = None

class DiscoverReq(BaseModel):
    cidr: str
    port: int = 161
    timeout: int = 2
    retries: int = 1
    workers: int = 128
    vlan_ports: str = "label"
    max_ports: int = 52
    snmp_v12c: Optional[SNMPv12c] = None
    snmp_v3: Optional[SNMPv3] = None

# ---------- Helpers ----------
def _maybe_cancel(job_key: Optional[str]) -> None:
    """Raise HTTP 499 if this job was cancelled."""
    if not job_key:
        return
    j = SCAN.get(job_key)
    if j and j.cancel:
        raise HTTPException(499, "Scan cancelled")

# Quick SNMP liveness check: try sysName once with current timeout/retries
# server.py
def _fast_snmp_ok(tgt, auth, timeout: int, retries: int) -> tuple[bool, object]:
    try:
        val = snmp_get(
            tgt, auth, OID["sysName"],
            timeout=timeout, retries=max(1, retries),
        )
        if val:
            return True, auth
    except Exception:
        pass

    # Fallback: if v2c failed, try v1
    if isinstance(auth, tuple):
        ver, comm = auth
        if str(ver).lower() == "2c":
            try:
                val = snmp_get(
                    tgt, ("1", comm), OID["sysName"],
                    timeout=timeout, retries=max(1, retries),
                )
                if val:
                    return True, ("1", comm)
            except Exception:
                pass

    return False, auth



def _auth_from_req(req) -> object:
    if getattr(req, "snmp_v3", None):
        v = req.snmp_v3
        return {
            "user": v.user,
            "auth_key": v.auth_key,
            "priv_key": v.priv_key,
            "auth_proto": v.auth_proto,
            "priv_proto": v.priv_proto,
        }
    if getattr(req, "snmp_v12c", None):
        v = req.snmp_v12c
        return (v.version, v.community)
    return ("2c", "public")  # default

async def _auth_from_form(req: Request):
    form = await req.form()
    ver = (form.get("snmp_version") or "2c").lower()
    if ver in ("1", "2c"):
        return (ver, form.get("community") or "public")
    # v3
    return {
        "user": form.get("v3_user") or "",
        "auth_key": form.get("v3_auth_key") or None,
        "priv_key": form.get("v3_priv_key") or None,
        "auth_proto": (form.get("v3_auth_proto") or "SHA").upper(),
        "priv_proto": (form.get("v3_priv_proto") or "AES").upper(),
    }

def _safe_excel_str(x):
    if x is None:
        return None
    if isinstance(x, bytes):
        try:
            x = x.decode("utf-8", "ignore")
        except Exception:
            x = x.decode("latin-1", "ignore")
    s = str(x)
    return ILLEGAL_CHARACTERS_RE.sub("", s)

def _iflabel_map(tgt, auth, timeout, retries):
    _, if_labels = build_ifindex_maps(tgt, auth, timeout, retries)
    return {int(k): v for k, v in (if_labels or {}).items()}

def _serialize_host(
    target: str,
    auth,
    port: int,
    timeout: int,
    retries: int,
    max_ports: int,
    vlan_ports: str,
    job_key: Optional[str] = None,   # ← NEW (optional)
) -> Dict[str, Any]:
    tgt = transport(target, port, timeout, retries)

    _maybe_cancel(job_key)
    sys_name, sys_descr = get_device_header(tgt, auth, timeout, retries)

    _maybe_cancel(job_key)
    _, if_labels = build_ifindex_maps(tgt, auth, timeout, retries)

    _maybe_cancel(job_key)
    vlans = get_vlan_views(
        tgt, auth, timeout, retries,
        max_ports=max_ports,
        return_numeric=(vlan_ports == "numeric"),
    )

    _maybe_cancel(job_key)
    pvid_map = get_pvid_map(tgt, auth, timeout, retries)

    _maybe_cancel(job_key)
    rows = gather_interface_rows(tgt, auth, timeout, retries, pvid_map)

    _maybe_cancel(job_key)
    lldp = get_lldp_neighbors(tgt, auth, timeout, retries)

    _maybe_cancel(job_key)
    endpoints = []
    try:
        fdb = get_fdb_entries(
            tgt, auth,
            timeout=timeout,
            retries=retries,
            include_non_dynamic=False,
            oui_db_path=OUI_DB_PATH,  # uses full OUI DB if configured
        )
        for e in fdb:
            endpoints.append({
                "mac": e.mac,
                "vendor": e.vendor or "Unknown",
                "vlan": e.vlan,
                "ifIndex": e.ifIndex,
                "ifName": if_labels.get(e.ifIndex) if e.ifIndex is not None else None,
                "status": e.status,
            })
    except Exception:
        endpoints = []

    return {
        "target": target,
        "sys_name": sys_name,
        "sys_descr": sys_descr,
        "vlans": [
            {"vid": v.vid, "name": v.name,
             "untagged": list(v.untagged or []),
             "tagged": list(v.tagged or [])}
            for v in (vlans or [])
        ],
        "pvid_map": pvid_map or {},
        "interfaces": [
            {
                "ifIndex": r.ifIndex, "name": r.name, "alias": r.alias,
                "admin": r.admin, "oper": r.oper, "speed": r.speed, "mtu": r.mtu,
                "duplex": r.duplex, "pvid": r.pvid, "in_bytes": r.in_bytes,
                "out_bytes": r.out_bytes, "in_err": r.in_err, "out_err": r.out_err,
                "mac": r.mac, "last_change": r.last_change, "neighbors": r.neighbors,
            } for r in (rows or [])
        ],
        "lldp_neighbors": lldp or {},
        "endpoints": endpoints,
    }


def _latest_host_payload_for_ip(s: Session, ip: str) -> Optional[Dict[str, Any]]:
    scans = s.exec(select(Scan).order_by(Scan.id.desc()).limit(500)).all()
    for sc in scans:
        try:
            res = sc.result or {}
            if sc.mode == "single":
                host = res.get("host") or {}
                if host.get("target") == ip:
                    return host
            else:
                for h in res.get("hosts", []):
                    if h.get("target") == ip:
                        return h
        except Exception:
            continue
    return None

def _device_index_by_sysname(s: Session) -> Dict[str, str]:
    out: Dict[str, str] = {}
    rows = s.exec(select(Device)).all()
    for d in rows:
        if d.sys_name:
            out[d.sys_name] = d.ip
    return out

def _collect_latest_lldp_for_all(s: Session) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    result: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    devs = s.exec(select(Device)).all()
    for d in devs:
        payload = _latest_host_payload_for_ip(s, d.ip)
        if not payload:
            continue
        lldp = payload.get("lldp_neighbors") or {}
        if lldp:
            result[d.ip] = lldp
    return result

def _ui_require_login(req: Request, next_path: str = "/") -> Response | None:
    try:
        require_user(req)
        return None

    except HTTPException as e:
        if e.status_code in (401, 403):
            resp = RedirectResponse(
                url=f"/login?next={next_path}",
                status_code=303,
            )

            # Kill expired cookie so browser stops re-sending it
            resp.delete_cookie(
                key=AUTH_COOKIE,
                path="/",
                secure=COOKIE_SECURE,
                samesite=COOKIE_SAMESITE,
            )
            return resp
        raise

# ---------- Lifecycle ----------
@app.on_event("startup")
def _startup():
    lvl = os.getenv("LOG_LEVEL", "INFO")
    log_file = os.getenv("LOG_FILE")
    setup_logging(level=lvl, log_file=log_file)
    attach_ui_log_buffer(max_lines=int(os.getenv("UI_LOG_LINES", "2000")))
    init_db()
    log.info("snmp-magic API started. LOG_LEVEL=%s LOG_FILE=%s", lvl, log_file or "None")

# ---------- Basic health ----------
@app.get("/health")
def health():
    return {"ok": True}


# --- Schedules ---
@app.get("/schedules/ui", response_class=HTMLResponse)
def ui_schedules(req: Request):
    return templates.TemplateResponse("schedules.html", {"request": req})


# ---------- Scans ----------
@app.post("/scan/host", dependencies=[Depends(require_user), Depends(require_api_key), Depends(rate_limiter_dep)])
def scan_host(req: ScanHostReq):
    auth = _auth_from_req(req)
    key = f"host:{req.target}"
    SCAN.start(key)
    try:
        log.info("SCAN host start target=%s port=%s timeout=%s retries=%s", req.target, req.port, req.timeout, req.retries)
        tgt = transport(req.target, req.port, req.timeout, req.retries)

        if _cancelled(key):
            raise HTTPException(499, "Scan cancelled")

        # Ping first (non-fatal for UI, but here we keep current behavior)
        if not ping_host(req.target, timeout_ms=600):
            log.warning("SCAN host ping failed target=%s", req.target)
            payload = {"mode": "single", "host": {"target": req.target}, "error": "Ping failed"}
            scan_id = save_scan(payload, "single", req.target, "error")
            payload["scan_id"] = scan_id
            return payload

        if _cancelled(key):
            raise HTTPException(499, "Scan cancelled")

        # --- Liveness + v2c→v1 fallback on sysName ---
        auth_used = auth
        name_try = snmp_get(tgt, auth_used, OID["sysName"], timeout=req.timeout, retries=max(1, req.retries))
        if not name_try and isinstance(auth_used, tuple):
            ver, comm = auth_used
            if str(ver).lower() == "2c":
                v1_auth = ("1", comm)
                name_v1 = snmp_get(tgt, v1_auth, OID["sysName"], timeout=req.timeout, retries=max(1, req.retries))
                if name_v1:
                    auth_used = v1_auth
                    name_try = name_v1  # success with v1

        if not name_try:
            log.warning("SCAN host SNMP liveness failed target=%s", req.target)
            payload = {"mode": "single", "host": {"target": req.target}, "error": "SNMP not responding (sysName)"}
            scan_id = save_scan(payload, "single", req.target, "error")
            payload["scan_id"] = scan_id
            return payload

        if _cancelled(key):
            raise HTTPException(499, "Scan cancelled")

        # Use the working auth for the full serialization
        host = _serialize_host(
            req.target, auth_used, req.port, req.timeout, req.retries, req.max_ports, req.vlan_ports
        )
        log.info("SCAN host finished target=%s sysName=%s ifaces=%d vlans=%d",
                 req.target, host.get("sys_name"), len(host.get("interfaces") or []), len(host.get("vlans") or []))

        # Enrich endpoints using the same auth that worked
        tgt_labels = transport(req.target, req.port, req.timeout, req.retries)
        labels = _iflabel_map(tgt_labels, auth_used, req.timeout, req.retries)
        fdb = get_fdb_entries(
            tgt_labels, auth_used, timeout=req.timeout, retries=req.retries,
            include_non_dynamic=False, oui_db_path=OUI_DB_PATH
        )
        host["endpoints"] = [{
            "mac": e.mac, "vendor": e.vendor or "Unknown", "vlan": e.vlan,
            "ifIndex": e.ifIndex, "ifName": labels.get(e.ifIndex) if e.ifIndex is not None else None,
            "status": e.status,
        } for e in fdb]
        log.info("SCAN host endpoints target=%s count=%d", req.target, len(host["endpoints"]))

        payload = {"mode": "single", "host": host}
        scan_id = save_scan(payload, "single", req.target, "ok")
        payload["scan_id"] = scan_id
        return payload
    finally:
        SCAN.clear(key)


# Stop/cancel scans
@app.post("/scan/stop", dependencies=[Depends(require_user), Depends(require_api_key)])
def scan_stop(
    kind: str = Query(..., pattern="^(host|discover)$"),
    key: str = Query("", description="For host: target IP. For discover: CIDR."),
):
    if not key.strip():
        return {
            "error": "Missing 'key'. Use target IP (host) or CIDR (discover).",
            "examples": {
                "host": "/scan/stop?kind=host&key=192.168.1.50",
                "discover": "/scan/stop?kind=discover&key=192.168.1.0/24",
            },
            "active_keys": SCAN.list_keys(),
        }
    job_key = f"{kind}:{key}"
    if not SCAN.get(job_key):
        raise HTTPException(404, detail={"error": f"No running scan '{job_key}'", "active_keys": SCAN.list_keys()})
    SCAN.stop(job_key)
    return {"ok": True, "stopped": job_key}

# Discovery scan
@app.post("/scan/discover", dependencies=[Depends(require_user), Depends(require_api_key), Depends(rate_limiter_dep)])
def scan_discover(req: DiscoverReq):
    auth = _auth_from_req(req)
    job_key = f"discover:{req.cidr}"
    SCAN.start(job_key)
    try:
        probes = discover_cidr(
            req.cidr, auth, port=req.port, timeout=req.timeout,
            retries=max(1, req.retries), workers=max(1, req.workers),
        )
        scan_list = [p.ip for p in probes if p.ping_ok and p.snmp_ok]

        hosts = []
        for ip in scan_list:
            j = SCAN.get(job_key)
            if j and j.cancel:
                break
            host_payload = _serialize_host(
                ip, auth, req.port, req.timeout, max(1, req.retries),
                req.max_ports, req.vlan_ports
            )
            hosts.append(host_payload)

        payload = {
            "mode": "discovery",
            "cidr": req.cidr,
            "probes": [
                {"ip": p.ip, "ping_ok": p.ping_ok, "snmp_ok": p.snmp_ok,
                 "sys_name": p.sys_name, "sys_descr": p.sys_descr}
                for p in probes
            ],
            "hosts": hosts,
        }
        scan_id = save_scan(payload, "discovery", req.cidr, "ok")
        payload["scan_id"] = scan_id
        return payload
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        SCAN.clear(job_key)

# ---------- Devices ----------
@app.get("/api/devices", dependencies=[Depends(require_user)])
def list_devices(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: Optional[str] = Query(None, description="substring match on sys_name or ip"),
):
    with Session(engine) as s:
        stmt = select(Device).order_by(Device.last_seen.desc())
        if q:
            stmt = stmt.where((Device.ip.contains(q)) | (Device.sys_name.contains(q)))
        rows = s.exec(stmt.offset(offset).limit(limit)).all()
        return rows

@app.get("/api/devices/{ip}", dependencies=[Depends(require_user)])
def get_device_details(ip: str = FPath(..., pattern=r"\d{1,3}(?:\.\d{1,3}){3}")):
    with Session(engine) as s:
        d = s.exec(select(Device).where(Device.ip == ip)).first()
        if not d:
            raise HTTPException(404, f"No device {ip}")
        latest = _latest_host_payload_for_ip(s, ip)
        return {"device": d, "latest_payload": latest}

@app.delete("/api/devices/{ip}", response_class=HTMLResponse, dependencies=[Depends(require_user)])
async def delete_device(
    request: Request,
    ip: str,
    q: str = "",
    sort_by: str = "last_seen",
    order: str = "desc",
):
    with Session(engine) as s:
        d = s.exec(select(Device).where(Device.ip == ip)).first()
        if d:
            s.delete(d)
            s.commit()

        stmt = select(Device)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(
                (Device.ip.like(like)) |
                (Device.sys_name.like(like)) |
                (Device.sys_descr.like(like))
            )
        col = Device.ip if sort_by == "ip" else getattr(Device, sort_by)
        stmt = stmt.order_by(col.asc() if order == "asc" else col.desc())
        rows = s.exec(stmt).all()

    return templates.TemplateResponse(
        "_device_table.html",
        {"request": request, "rows": rows, "q": q, "sort_by": sort_by, "order": order},
    )


# only interfaces (fast for UI tab)
@app.get("/api/devices/{ip}/interfaces", dependencies=[Depends(require_user)])
def get_device_interfaces(ip: str = FPath(..., pattern=r"\d{1,3}(?:\.\d{1,3}){3}")):
    with Session(engine) as s:
        d = s.exec(select(Device).where(Device.ip == ip)).first()
        if not d:
            raise HTTPException(404, f"No device {ip}")
        latest = _latest_host_payload_for_ip(s, ip) or {}
        return latest.get("interfaces", [])

# only VLANs + PVID map (fast for UI tab)
@app.get("/api/devices/{ip}/vlans", dependencies=[Depends(require_user)])
def get_device_vlans(ip: str = FPath(..., pattern=r"\d{1,3}(?:\.\d{1,3}){3}")):
    with Session(engine) as s:
        d = s.exec(select(Device).where(Device.ip == ip)).first()
        if not d:
            raise HTTPException(404, f"No device {ip}")
        latest = _latest_host_payload_for_ip(s, ip) or {}
        return {
            "vlans": latest.get("vlans", []),
            "pvid_map": latest.get("pvid_map", {}),
            "sys_name": (latest.get("sys_name") or d.sys_name),
        }

@app.get("/api/devices/{ip}/endpoints", dependencies=[Depends(require_user)])
def api_device_endpoints(ip: str, community: str = "public", version: str = "2c", timeout: int = 3, retries: int = 2):
    tgt = transport(ip, 161, timeout=timeout, retries=retries)
    auth = (version, community)
    labels = _iflabel_map(tgt, auth, timeout, retries)
    fdb = get_fdb_entries(
        tgt, auth, timeout=timeout, retries=retries,
        include_non_dynamic=False, oui_db_path=OUI_DB_PATH
    )
    rows = [{
        "mac": e.mac,
        "vendor": e.vendor or "Unknown",
        "vlan": e.vlan,
        "ifIndex": e.ifIndex,
        "ifName": labels.get(e.ifIndex) if e.ifIndex is not None else None,
        "status": e.status,
    } for e in fdb]
    return {"ip": ip, "count": len(rows), "endpoints": rows}

# ---------- Scans history ----------
@app.get("/scans", dependencies=[Depends(require_user)])
def list_scans(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    mode: Optional[str] = Query(None, description="single|discovery"),
    target: Optional[str] = Query(None, description="host IP or CIDR contains"),
):
    with Session(engine) as s:
        stmt = select(Scan).order_by(Scan.id.desc())
        if mode:
            stmt = stmt.where(Scan.mode == mode)
        if target:
            stmt = stmt.where(Scan.target.contains(target))
        rows = s.exec(stmt.offset(offset).limit(limit)).all()
        return rows

@app.get("/scans/{scan_id}", dependencies=[Depends(require_user)])
def get_scan(scan_id: int):
    with Session(engine) as s:
        row = s.get(Scan, scan_id)
        if not row:
            raise HTTPException(404, f"No scan with id={scan_id}")
        return row

# ---------- Topology (LLDP) ----------
@app.get("/topology/lldp", dependencies=[Depends(require_user)])
def lldp_topology():
    with Session(engine) as s:
        lldp_by_ip = _collect_latest_lldp_for_all(s)
        if not lldp_by_ip:
            return {"nodes": [], "edges": []}

        sysname_to_ip = _device_index_by_sysname(s)

        nodes: Dict[str, Dict[str, str]] = {}
        devs = s.exec(select(Device)).all()
        for d in devs:
            label = d.sys_name or d.ip
            nodes[d.ip] = {"id": d.ip, "label": label, "type": "device"}

        edges: List[Dict[str, str]] = []
        for local_ip, neigh_map in lldp_by_ip.items():
            for local_if_label, peers in neigh_map.items():
                for peer in peers:
                    peer_name = (peer.get("sysName") or "").strip() or "?"
                    port_id = (peer.get("portId") or "").strip()
                    desc = (peer.get("portDesc") or "").strip()

                    target_ip = sysname_to_ip.get(peer_name)
                    if not target_ip:
                        synthetic_id = f"ext:{peer_name}"
                        if synthetic_id not in nodes:
                            nodes[synthetic_id] = {"id": synthetic_id, "label": peer_name, "type": "external"}
                        target_ip = synthetic_id

                    edges.append({
                        "source": local_ip,
                        "target": target_ip,
                        "local_if": local_if_label,
                        "desc": desc or port_id,
                    })

        return {"nodes": list(nodes.values()), "edges": edges}

# ---------- Metrics ----------
@app.get("/metrics")
def metrics():
    with Session(engine) as s:
        devices_count = s.exec(select(func.count(Device.id))).one()[0]
        scans_count   = s.exec(select(func.count(Scan.id))).one()[0]
        last_scan = s.exec(select(Scan).order_by(Scan.id.desc()).limit(1)).first()
        return {
            "devices": devices_count,
            "scans": scans_count,
            "last_scan_id": getattr(last_scan, "id", None),
            "last_scan_at_utc": getattr(last_scan, "finished_at", None),
            "now_utc": datetime.utcnow().isoformat() + "Z",
        }

def _df(rows: Iterable[dict]) -> "pd.DataFrame":
    try:
        df = pd.DataFrame(list(rows))
        try:
            return df.applymap(lambda v: ILLEGAL_CHARACTERS_RE.sub("", v) if isinstance(v, str) else v)
        except Exception:
            return df
    except Exception:
        return pd.DataFrame()

def _xlsx_response(buf: io.BytesIO, filename: str) -> StreamingResponse:
    buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers=headers,
    )

@app.get("/export/devices.xlsx", dependencies=[Depends(require_user)])
def export_all_devices():
    with Session(engine) as s:
        devs = s.exec(select(Device).order_by(Device.last_seen.desc())).all()
        dev_dicts = [{"ip": d.ip, "sys_name": d.sys_name, "sys_descr": d.sys_descr,
                      "first_seen": d.first_seen, "last_seen": d.last_seen} for d in devs]
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        _df(dev_dicts).to_excel(xw, sheet_name="Devices", index=False)
    return _xlsx_response(buf, "devices.xlsx")

@app.get("/export/device/{ip}.xlsx", dependencies=[Depends(require_user)])
def export_one_device(ip: str):
    with Session(engine) as s:
        payload = _latest_host_payload_for_ip(s, ip)
        if not payload:
            raise HTTPException(404, f"No data for {ip}")

    meta = [{"target": payload.get("target"),
             "sys_name": payload.get("sys_name"),
             "sys_descr": payload.get("sys_descr")}]

    interfaces = payload.get("interfaces") or []
    vlans = payload.get("vlans") or []
    pvid_map = payload.get("pvid_map") or {}
    pvid_rows = [{"ifIndex": int(k), "PVID": v} for k, v in pvid_map.items()]

    lldp_rows = []
    for loc_if, peers in (payload.get("lldp_neighbors") or {}).items():
        for p in peers:
            lldp_rows.append({
                "local_if":      _safe_excel_str(loc_if),
                "peer_sysName":  _safe_excel_str(p.get("sysName")),
                "peer_portId":   _safe_excel_str(p.get("portId")),
                "peer_portDesc": _safe_excel_str(p.get("portDesc")),
            })

    endpoints = payload.get("endpoints") or []
    from collections import defaultdict as _dd
    eps_by_if = _dd(list)
    for e in endpoints:
        idx = e.get("ifIndex")
        if idx is not None:
            eps_by_if[idx].append(e)

    interfaces_enriched = []
    for r in interfaces:
        rr = dict(r) if isinstance(r, dict) else dict(r._asdict())
        idx = rr.get("ifIndex")
        eps = eps_by_if.get(idx, [])
        macs = [e.get("mac") for e in eps if e.get("mac")]
        vendors = sorted({(e.get("vendor") or "Unknown") for e in eps})
        vl_set = sorted({str(e.get("vlan")) for e in eps if e.get("vlan") is not None})
        rr["endpoint_count"] = len(eps)
        rr["endpoint_macs"] = ", ".join(macs)
        rr["endpoint_vendors"] = ", ".join(vendors)
        rr["endpoint_vlans"] = ", ".join(vl_set)
        interfaces_enriched.append(rr)

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        _df(meta).to_excel(xw, sheet_name="Meta", index=False)
        _df(interfaces_enriched).to_excel(xw, sheet_name="Interfaces", index=False)
        _df(vlans).to_excel(xw, sheet_name="VLANs", index=False)
        _df(pvid_rows).to_excel(xw, sheet_name="PVID", index=False)
        _df(lldp_rows).to_excel(xw, sheet_name="LLDP", index=False)

    safe_ip = ip.replace(":", "_")
    return _xlsx_response(buf, f"device_{safe_ip}.xlsx")

# =====================================================================
# ======================  Minimal HTML GUI (Jinja + HTMX)  ============
# =====================================================================
@app.get("/", response_class=HTMLResponse)
def ui_dashboard(req: Request):
    r = _ui_require_login(req, "/")
    if r:
        return r
    return templates.TemplateResponse(
        "index.html",
        {"request": req, "active": "dashboard"},
    )


@app.get("/devices/ui", response_class=HTMLResponse)
def ui_devices(req: Request, q: str = Query("", alias="q")):
    # preserve query in next so user returns to same search
    next_path = "/devices/ui" + (f"?q={q}" if q else "")
    r = _ui_require_login(req, next_path)
    if r:
        return r

    return templates.TemplateResponse(
        "devices.html",
        {"request": req, "q": q, "active": "devices"},
    )


@app.get("/devices/{ip}/ui", response_class=HTMLResponse)
def ui_device_detail(req: Request, ip: str):
    next_path = f"/devices/{ip}/ui"
    r = _ui_require_login(req, next_path)
    if r:
        return r

    return templates.TemplateResponse(
        "device_detail.html",
        {"request": req, "ip": ip},
    )


@app.get("/topology/ui", response_class=HTMLResponse)
def ui_topology(req: Request):
    r = _ui_require_login(req, "/topology/ui")
    if r:
        return r

    return templates.TemplateResponse(
        "topology.html",
        {"request": req, "active": "topology"},
    )

@app.post(
    "/ui/scan",
    response_class=HTMLResponse,
    dependencies=[Depends(rate_limiter_dep,), Depends(require_user)]
)
async def ui_scan(req: Request):
    form = await req.form()
    mode = (form.get("mode") or "host").lower()
    port = int(form.get("port") or 161)
    timeout = int(form.get("timeout") or 2)
    retries = int(form.get("retries") or 2)
    max_ports = int(form.get("max_ports") or 52)
    vlan_ports = form.get("vlan_ports") or "label"

    auth = await _auth_from_form(req)

    try:
        if mode == "host":
            target = (form.get("target") or "").strip()
            log.info("UI scan start target=%s port=%s timeout=%s retries=%s", target, port, timeout, retries)

            # 1) Try ping, but don't hard-fail; many environments block ICMP.
            ping_ok = ping_host(target, timeout_ms=600)
            if not ping_ok:
                log.warning("UI scan ping failed (continuing anyway) target=%s", target)

            # 2) SNMP liveness (sysName) with snappy UI settings
            ui_timeout = max(1, min(timeout, 2))   # keep each SNMP op quick for UI
            ui_retries = 1
            tgt = transport(target, port, ui_timeout, ui_retries)
            snmp_ok = _fast_snmp_ok(tgt, auth, ui_timeout, ui_retries)

            if not snmp_ok and not ping_ok:
                payload = {"mode": "single", "host": {"target": target}, "error": "Neither ping nor SNMP responded"}
                scan_id = save_scan(payload, "single", target, "error")
                log.warning("UI scan failed (no ping/SNMP) target=%s scan_id=%s", target, scan_id)
                return templates.TemplateResponse(
                    "_scan_result.html",
                    {
                        "request": req,
                        "title": "Scan failed",
                        "error": f"Neither ping nor SNMP responded on {target}. Check connectivity/credentials.",
                        "lines": [f"Scan ID: {scan_id}"],
                        "links": [],
                    },
                    status_code=400,
                )

            if not snmp_ok:
                payload = {"mode": "single", "host": {"target": target}, "error": "SNMP not responding (sysName)"}
                scan_id = save_scan(payload, "single", target, "error")
                log.warning("UI scan failed (SNMP liveness) target=%s scan_id=%s", target, scan_id)
                return templates.TemplateResponse(
                    "_scan_result.html",
                    {
                        "request": req,
                        "title": "Scan failed",
                        "error": f"SNMP not responding (sysName) on {target}. Check community/user/ACL.",
                        "lines": [f"Scan ID: {scan_id}"],
                        "links": [],
                    },
                    status_code=400,
                )

            # 3) Run full serialize with a more realistic overall cap for UI
            overall_cap = int(os.getenv("UI_SCAN_CAP", "60"))  # 60s default
            job_key = f"ui:{target}"
            SCAN.start(job_key)

            try:
                # Run sync serialization in a worker thread (safe in FastAPI)
                
                fn = functools.partial(
                    _serialize_host,
                    target, auth, port, ui_timeout, ui_retries,
                    max_ports, vlan_ports,
                    job_key=job_key,
                )
                host = await asyncio.wait_for(
                anyio.to_thread.run_sync(fn),
                 timeout=overall_cap,
                )
            except asyncio.TimeoutError:
                SCAN.stop(job_key)
                payload = {"mode": "single", "host": {"target": target}, "error": f"UI scan timeout ({overall_cap}s)"}
                scan_id = save_scan(payload, "single", target, "error")
                log.error("UI scan timed out target=%s cap=%ss scan_id=%s", target, overall_cap, scan_id)
                return templates.TemplateResponse(
                    "_scan_result.html",
                    {
                        "request": req,
                        "title": "Scan timed out",
                        "error": f"Scan exceeded {overall_cap}s on {target}. Try lowering timeout/retries.",
                        "lines": [f"Scan ID: {scan_id}"],
                        "links": [],
                    },
                    status_code=504,
                )
            finally:
                SCAN.clear(job_key)

            # 4) Success — persist and show result
            payload = {"mode": "single", "host": host}
            scan_id = save_scan(payload, "single", target, "ok")
            log.info("UI scan complete target=%s scan_id=%s", target, scan_id)

            return templates.TemplateResponse(
                "_scan_result.html",
                {
                    "request": req,
                    "title": "Host scan complete",
                    "lines": [
                        f"Target: {host.get('target')}",
                        f"sysName: {host.get('sys_name') or '-'}",
                        f"Interfaces: {len(host.get('interfaces') or [])}",
                        f"VLANs: {len(host.get('vlans') or [])}",
                        f"Scan ID: {scan_id}",
                    ],
                    "links": [
                        {"href": f"/devices/{host.get('target')}/ui", "label": "Open device"},
                        {"href": "/devices/ui", "label": "All devices"},
                    ],
                },
            )

        # --- discovery path unchanged ---
        else:
            cidr = (form.get("cidr") or "").strip()
            workers = int(form.get("workers") or 128)
            log.info("UI discovery start cidr=%s workers=%s", cidr, workers)
            probes = discover_cidr(cidr, auth, port, timeout, max(1, retries), workers=workers)
            scan_list = [p.ip for p in probes if p.ping_ok and p.snmp_ok]
            hosts = [
                _serialize_host(ip, auth, port, max(1, min(timeout, 2)), 1, max_ports, vlan_ports)
                for ip in scan_list
            ]
            payload = {
                "mode": "discovery",
                "cidr": cidr,
                "probes": [
                    {"ip": p.ip, "ping_ok": p.ping_ok, "snmp_ok": p.snmp_ok,
                     "sys_name": p.sys_name, "sys_descr": p.sys_descr}
                    for p in probes
                ],
                "hosts": hosts,
            }
            scan_id = save_scan(payload, "discovery", cidr, "ok")
            log.info("UI discovery complete cidr=%s hosts_scanned=%d scan_id=%s", cidr, len(hosts), scan_id)
            return templates.TemplateResponse(
                "_scan_result.html",
                {
                    "request": req,
                    "title": "Discovery complete",
                    "lines": [
                        f"CIDR: {cidr}",
                        f"Pingable: {sum(1 for p in probes if p.ping_ok)}",
                        f"SNMP-capable: {len(scan_list)}",
                        f"Scanned: {len(hosts)} host(s)",
                        f"Scan ID: {scan_id}",
                    ],
                    "links": [{"href": "/devices/ui", "label": "Open devices"}],
                },
            )

    except Exception as e:
        log.exception("UI scan failed: %s", e)
        try:
            target = (form.get("target") or form.get("cidr") or "").strip()
            payload = {"mode": "single", "host": {"target": target}, "error": str(e)}
            save_scan(payload, "single", target, "error")
        except Exception:
            pass

        return templates.TemplateResponse(
            "_scan_result.html",
            {"request": req, "title": "Scan failed", "error": str(e), "lines": [], "links": []},
            status_code=500,
        )

# Logs endpoints
@app.get("/logs/tail")
def ui_logs_tail(offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)):
    next_off, lines = get_ui_logs_from(offset)
    if len(lines) > limit:
        lines = lines[-limit:]
    return {"next_offset": next_off, "lines": lines}

@app.get("/logs/stream")
async def ui_logs_stream():
    async def eventgen():
        offset = 0
        while True:
            next_off, lines = get_ui_logs_from(offset)
            if lines:
                yield f"data: {chr(10).join(lines)}\n\n"
                offset = next_off
            await asyncio.sleep(1.0)
    return StreamingResponse(eventgen(), media_type="text/event-stream")

# --------- HTMX partials (HTML snippets) ----------
@app.get("/ui/panels/metrics", response_class=HTMLResponse)
def ui_metrics_panel(req: Request):
    with Session(engine) as s:
        # robust COUNT(*) that works across SQLAlchemy versions
        def _count(model):
            res = s.exec(select(func.count()).select_from(model))
            try:
                return res.scalar_one()
            except Exception:
                # fallback if scalar_one() isn't available in this env
                v = res.one()
                return v[0] if isinstance(v, (tuple, list)) else int(v)

        devices_count = _count(Device)
        scans_count   = _count(Scan)
        last_scan = s.exec(select(Scan).order_by(Scan.id.desc()).limit(1)).first()

    return templates.TemplateResponse(
        "_metrics_panel.html",
        {
            "request": req,
            "devices_count": devices_count,
            "scans_count": scans_count,
            "last_scan": getattr(last_scan, "finished_at", None),
        },
    )



@app.get("/ui/partials/device-table", response_class=HTMLResponse)
def ui_device_table(
    req: Request,
    q: str = "",
    sort_by: str = Query("last_seen", pattern="^(ip|sys_name|first_seen|last_seen)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
):
    with Session(engine) as s:
        stmt = select(Device)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(
                (Device.ip.like(like)) |
                (Device.sys_name.like(like)) |
                (Device.sys_descr.like(like))
            )
        col = Device.ip if sort_by == "ip" else getattr(Device, sort_by)
        stmt = stmt.order_by(col.asc() if order == "asc" else col.desc())
        rows = s.exec(stmt).all()

    return templates.TemplateResponse("_device_table.html", {
        "request": req,
        "rows": rows,
        "q": q,
        "sort_by": sort_by,
        "order": order,
    })

@app.get("/ui/partials/{ip}/interfaces", response_class=HTMLResponse)
def ui_interfaces_table(req: Request, ip: str):
    with Session(engine) as s:
        sc = s.exec(select(Scan).where(Scan.target == ip).order_by(Scan.finished_at.desc())).first()

    data = (sc.result or {}).get("host") or (sc.result if sc else {}) or {}
    rows = data.get("interfaces", []) or []
    endpoints = data.get("endpoints", []) or []

    from collections import Counter, defaultdict
    counts = Counter(e.get("ifIndex") for e in endpoints if isinstance(e, dict) and e.get("ifIndex") is not None)
    macs_by_if = defaultdict(list)
    for e in endpoints:
        if not isinstance(e, dict):
            continue
        idx = e.get("ifIndex")
        mac = e.get("mac")
        if idx is None or not mac:
            continue
        macs_by_if[idx].append(mac)

    for r in rows:
        if not isinstance(r, dict):
            continue
        idx = r.get("ifIndex")
        cnt = int(counts.get(idx, 0))
        r["endpoint_count"] = cnt
        if 0 < cnt <= 10:
            dedup = list(dict.fromkeys(macs_by_if.get(idx, [])))[:10]
            r["endpoint_macs"] = ", ".join(dedup)
        else:
            r["endpoint_macs"] = ""

    total_endpoints = sum(counts.values())
    community = req.query_params.get("community", "public")
    version = req.query_params.get("version", "2c")

    return templates.TemplateResponse(
        "_interfaces_table.html",
        {"request": req, "ip": ip, "rows": rows, "total_endpoints": total_endpoints,
         "community": community, "version": version}
    )

@app.get("/ui/partials/{ip}/vlans", response_class=HTMLResponse)
def ui_vlans_table(req: Request, ip: str):
    with Session(engine) as s:
        sc = s.exec(select(Scan).where(Scan.target == ip).order_by(Scan.finished_at.desc())).first()
    data = (sc.result or {}).get("host") or (sc.result if sc else {})
    vlans = (data or {}).get("vlans", [])
    pvid = (data or {}).get("pvid_map", {})
    return templates.TemplateResponse("_vlans_table.html", {"request": req, "vlans": vlans, "pvid": pvid})

@app.get("/ui/partials/{ip}/lldp", response_class=HTMLResponse)
def ui_lldp_list(req: Request, ip: str):
    with Session(engine) as s:
        sc = s.exec(select(Scan).where(Scan.target == ip).order_by(Scan.finished_at.desc())).first()
    data = (sc.result or {}).get("host") or (sc.result if sc else {})
    lldp = (data or {}).get("lldp_neighbors", {})
    return templates.TemplateResponse("_lldp_list.html", {"request": req, "lldp": lldp})

# Endpoints tab (HTML)
@app.get("/ui/devices/{ip}/endpoints")
def ui_device_endpoints(
    ip: str,
    request: Request,
    community: str = "public",
    version: str = "2c",
    timeout: int = 3,
    retries: int = 2,
    ifIndex: Optional[int] = None,
    vlan: Optional[int] = None,
):
    tgt = transport(ip, 161, timeout=timeout, retries=retries)
    auth = (version, community)
    labels = _iflabel_map(tgt, auth, timeout, retries)
    fdb = get_fdb_entries(
        tgt, auth, timeout=timeout, retries=retries,
        include_non_dynamic=False, oui_db_path=OUI_DB_PATH
    )
    rows = [{
        "mac": e.mac, "vendor": e.vendor or "Unknown", "vlan": e.vlan,
        "ifIndex": e.ifIndex, "ifName": labels.get(e.ifIndex) if e.ifIndex is not None else None,
        "status": e.status,
    } for e in fdb]

    if ifIndex is not None:
        rows = [r for r in rows if r.get("ifIndex") == ifIndex]
    if vlan is not None:
        rows = [r for r in rows if r.get("vlan") == vlan]

    return templates.TemplateResponse(
        "partials/endpoints.html",
        {"request": request, "ip": ip, "rows": rows, "count": len(rows),
         "community": community, "version": version, "timeout": timeout, "retries": retries,
         "active_ifIndex": ifIndex, "active_vlan": vlan}
    )

# --- optional: introspection endpoint for jobs ---
@app.get("/scan/jobs", dependencies=[Depends(require_user), Depends(require_api_key)])
def list_scan_jobs():
    return {"active": SCAN.list_keys()}
#==============================================
#==================AUTHENTICATION==============
#==============================================
@app.get("/login", response_class=HTMLResponse)
def ui_login(req: Request, next: str = "/"):
    # If already logged in (cookie exists), go straight to next
    token = req.cookies.get(AUTH_COOKIE)
    if token:
        return RedirectResponse(url=next, status_code=302)

    return templates.TemplateResponse(
        "login.html",
        {"request": req, "next": next, "error": ""},
    )


class _LoginForm(BaseModel):
    username: str
    password: str
    next: str = "/"


@app.post("/login")
async def ui_login_post(req: Request):
    form = await req.form()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    next_url = (form.get("next") or "/").strip() or "/"

    user_id = verify_user_password(username, password)
    if not user_id:
        # Render same page with error
        return templates.TemplateResponse(
            "login.html",
            {"request": req, "next": next_url, "error": "Invalid username or password."},
            status_code=401,
        )

    token = issue_token(user_id, ttl_hours=24 * 30, label="ui")
    resp = RedirectResponse(url=next_url, status_code=302)
    resp.set_cookie(
        key=AUTH_COOKIE,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=60 * 60 * 24 * 30,
        path="/",
    )
    return resp


@app.get("/logout")
def ui_logout(req: Request, next: str = "/login"):
    resp = RedirectResponse(url=next, status_code=302)
    resp.delete_cookie(AUTH_COOKIE, path="/")
    return resp