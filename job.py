# jobs.py
import uuid, threading, time
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=2)  # tune for your server
JOBS = {}  # job_id -> dict

def start_job(fn, *, args=None, kwargs=None):
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        "status": "queued",
        "percent": 0,
        "started_at": time.time(),
        "finished_at": None,
        "result_path": None,
        "error": None,
        "meta": {}
    }
    args = args or ()
    kwargs = kwargs or {}

    def progress(p=None, **meta):
        if p is not None:
            JOBS[job_id]["percent"] = max(0, min(100, int(p)))
        if meta:
            JOBS[job_id]["meta"].update(meta)

    def _run():
        JOBS[job_id]["status"] = "running"
        try:
            # fn must accept progress= callback
            result_path = fn(*args, progress=progress, **kwargs)
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["finished_at"] = time.time()
            JOBS[job_id]["result_path"] = result_path
            JOBS[job_id]["percent"] = 100
        except Exception as e:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["finished_at"] = time.time()
            JOBS[job_id]["error"] = str(e)

    executor.submit(_run)
    return job_id

def get_status(job_id):
    return JOBS.get(job_id, {"status":"unknown"})

def get_result_path(job_id):
    j = JOBS.get(job_id)
    return j and j.get("result_path")
