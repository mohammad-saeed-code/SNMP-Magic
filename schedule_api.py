# schedule_api.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any

from scheduler import (
    schedule_daily, schedule_cron, list_jobs, remove_job,
    pause_job, resume_job, run_job_now, schedule_daily_host
)

router = APIRouter()


class DailyReq(BaseModel):
    time: str = Field(..., description="HH:MM 24h (Europe/Paris)")
    params: Optional[Dict[str, Any]] = None
    job_id: Optional[str] = None

    @validator("time")
    def _validate_time(cls, v):
        parts = v.split(":")
        if len(parts) != 2:
            raise ValueError("time must be HH:MM")
        h, m = parts
        if not (h.isdigit() and m.isdigit()):
            raise ValueError("time must be numeric HH:MM")
        hi, mi = int(h), int(m)
        if not (0 <= hi <= 23 and 0 <= mi <= 59):
            raise ValueError("time out of range")
        return v


class CronReq(BaseModel):
    cron: str = Field(..., description="Crontab 'm h dom mon dow', e.g. '0 3 * * *'")
    params: Optional[Dict[str, Any]] = None
    job_id: Optional[str] = None


@router.post("/api/schedules/daily")
def create_daily(req: DailyReq):
    try:
        jid = schedule_daily(req.time, req.params, req.job_id)
        return {"ok": True, "job_id": jid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/schedules/cron")
def create_cron(req: CronReq):
    try:
        jid = schedule_cron(req.cron, req.params, req.job_id)
        return {"ok": True, "job_id": jid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/schedules")
def get_schedules():
    return list_jobs()


@router.delete("/api/schedules/{job_id}")
def delete_schedule(job_id: str):
    try:
        remove_job(job_id)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/api/schedules/{job_id}/pause")
def api_pause(job_id: str):
    try:
        pause_job(job_id)
        return {"ok": True, "job_id": job_id}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/api/schedules/{job_id}/resume")
def api_resume(job_id: str):
    try:
        resume_job(job_id)
        return {"ok": True, "job_id": job_id}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/api/schedules/{job_id}/run")
def api_run_now(job_id: str):
    try:
        run_job_now(job_id)
        return {"ok": True, "job_id": job_id}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


class DailyHostReq(BaseModel):
    time: str = Field(..., description="HH:MM 24h (Europe/Paris)")
    target: str
    version: Optional[str] = Field(None, description="'1' or '2c' or '3'")
    community: Optional[str] = None
    v3: Optional[Dict[str, Any]] = None
    port: int = 161
    timeout: int = 2
    retries: int = 2
    max_ports: int = 52
    vlan_ports: str = "label"
    job_id: Optional[str] = None

    @validator("time")
    def _validate_time(cls, v):
        parts = v.split(":")
        if len(parts) != 2:
            raise ValueError("time must be HH:MM")
        h, m = parts
        if not (h.isdigit() and m.isdigit()):
            raise ValueError("time must be numeric HH:MM")
        hi, mi = int(h), int(m)
        if not (0 <= hi <= 23 and 0 <= mi <= 59):
            raise ValueError("time out of range")
        return v


@router.post("/api/schedules/daily/host")
def create_daily_host(req: DailyHostReq):
    try:
        # build auth
        if (req.version in ("1", "2c")) or (req.version and req.community):
            auth = (req.version or "2c", req.community or "public")
        elif req.v3:
            auth = {
                "user": req.v3.get("user", ""),
                "auth_key": req.v3.get("auth_key"),
                "priv_key": req.v3.get("priv_key"),
                "auth_proto": (req.v3.get("auth_proto") or "SHA").upper(),
                "priv_proto": (req.v3.get("priv_proto") or "AES").upper(),
            }
        else:
            auth = ("2c", "public")

        params = {
            "target": req.target,
            "port": req.port,
            "timeout": req.timeout,
            "retries": req.retries,
            "max_ports": req.max_ports,
            "vlan_ports": req.vlan_ports,
            "auth": auth,
        }
        jid = schedule_daily_host(req.time, params, req.job_id)
        return {"ok": True, "job_id": jid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
