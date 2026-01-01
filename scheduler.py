# scheduler.py
import os
import logging
from typing import Optional, Dict, Any, List

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.cron import CronTrigger
from pytz import timezone

# your existing imports (keep as-is if they exist in your project)
from job import start_job
from discovery_entry import run as run_discovery
from snmp_magic.cli import scan_single_host
from snmp_magic.snmpio import transport
from snmp_magic.store import save_scan

log = logging.getLogger(__name__)
TZ = timezone("Europe/Paris")

_scheduler: Optional[BackgroundScheduler] = None


def _jobstore_url() -> str:
    """
    Persistent job store DB for APScheduler.
    IMPORTANT: this is NOT your scan-results DB unless you made it so.
    Use an absolute path to avoid 'different working directory' issues.
    """
    db_path = os.path.abspath("snmp_magic.db")
    return f"sqlite:///{db_path}"


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        jobstores = {"default": SQLAlchemyJobStore(url=_jobstore_url())}
        _scheduler = BackgroundScheduler(jobstores=jobstores, timezone=TZ, daemon=True)
        _scheduler.start()
        log.info("Scheduler started (persistent job store).")
    return _scheduler


# -----------------------------
# TOP-LEVEL JOB CALLABLES
# (No lambdas: required for persistence)
# -----------------------------

def run_discovery_job(params: Optional[Dict[str, Any]] = None):
    start_job(run_discovery, kwargs={"params": params or {}})


def run_single_host_job(params: Optional[Dict[str, Any]] = None):
    """
    params should contain:
      target, port, timeout, retries, max_ports, vlan_ports,
      auth (either tuple ('2c','public') or v3 dict)
    """
    params = params or {}
    target = params.get("target")
    if not target:
        raise ValueError("missing params.target")

    port = int(params.get("port", 161))
    timeout = int(params.get("timeout", 2))
    retries = int(params.get("retries", 2))
    max_ports = int(params.get("max_ports", 52))
    vlan_ports = params.get("vlan_ports", "label")

    auth = params.get("auth")
    if not auth:
        version = params.get("version", "2c")
        community = params.get("community", "public")
        auth = (version, community)

    # quick transport warmup (optional)
    transport(target, port, timeout, retries)

    log.info(f"[SCHED] scan_single_host target={target}")

    result = scan_single_host(
        target, auth, port, timeout, retries, max_ports, vlan_ports, collect=True
    ) or {}

    # Keep same payload structure you used earlier
    payload = {"mode": "single", "host": result}

    # save_scan should update last_seen etc (if it currently doesn't, we’ll fix next)
    save_scan(payload, "single", target, "ok")

    log.info(f"[SCHED] completed target={target}")


# -----------------------------
# SCHEDULING API (called by schedule_api.py)
# -----------------------------

def schedule_daily(time_hhmm: str, params: Optional[Dict[str, Any]] = None, job_id: Optional[str] = None) -> str:
    h, m = map(int, time_hhmm.split(":"))
    jid = job_id or f"scan-daily-{h:02d}{m:02d}"
    sch = get_scheduler()
    sch.add_job(
        run_discovery_job,
        trigger="cron",
        hour=h, minute=m,
        id=jid,
        replace_existing=True,
        kwargs={"params": params or {}},
    )
    return jid


def schedule_daily_host(time_hhmm: str, params: Optional[Dict[str, Any]] = None, job_id: Optional[str] = None) -> str:
    h, m = map(int, time_hhmm.split(":"))
    target = (params or {}).get("target", "unknown")
    jid = job_id or f"scan-host-{target}-{h:02d}{m:02d}"
    sch = get_scheduler()
    sch.add_job(
        run_single_host_job,
        trigger="cron",
        hour=h, minute=m,
        id=jid,
        replace_existing=True,
        kwargs={"params": params or {}},
    )
    return jid


def schedule_cron(cron: str, params: Optional[Dict[str, Any]] = None, job_id: Optional[str] = None) -> str:
    """
    cron: 'm h dom mon dow' (5-field crontab)
    """
    fields = cron.split()
    if len(fields) != 5:
        raise ValueError("cron must have 5 fields: 'm h dom mon dow'")

    minute, hour, day, month, dow = fields
    trigger = CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=dow, timezone=TZ)

    jid = job_id or f"scan-cron-{abs(hash(cron))}"
    sch = get_scheduler()
    sch.add_job(
        run_discovery_job,
        trigger=trigger,
        id=jid,
        replace_existing=True,
        kwargs={"params": params or {}},
    )
    return jid


def list_jobs() -> List[Dict[str, Any]]:
    sch = get_scheduler()
    out = []
    for j in sch.get_jobs():
        out.append({
            "id": j.id,
            "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None,
            "name": j.name,
            "trigger": str(j.trigger),
            "paused": (j.next_run_time is None),
        })
    return out


def remove_job(job_id: str):
    sch = get_scheduler()
    sch.remove_job(job_id)


def pause_job(job_id: str):
    sch = get_scheduler()
    sch.pause_job(job_id)


def resume_job(job_id: str):
    sch = get_scheduler()
    sch.resume_job(job_id)


def run_job_now(job_id: str):
    """
    FIXED: runs the stored callable WITH its args/kwargs,
    so it won’t fail with 'missing params'.
    """
    sch = get_scheduler()
    job = sch.get_job(job_id)
    if not job:
        raise KeyError(f"Job not found: {job_id}")
    return job.func(*job.args, **job.kwargs)
