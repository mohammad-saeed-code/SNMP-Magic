# scan_api.py (FastAPI)
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
import json, time

from job import start_job, get_status, get_result_path
from discovery_entry import run as run_discovery

router = APIRouter()

@router.post("/api/scan")
async def create_scan(request: Request):
    body = await request.json()
    job_id = start_job(run_discovery, kwargs={"params": body})
    return {"job_id": job_id}

@router.get("/api/scan/{job_id}/status")
def scan_status(job_id: str):
    return get_status(job_id)

@router.get("/api/scan/{job_id}/result")
def scan_result(job_id: str):
    path = get_result_path(job_id)
    if not path:
        return JSONResponse({"error":"not ready"}, status_code=404)
    return FileResponse(path, filename=path.rsplit("/",1)[-1], media_type="application/json")

@router.get("/api/scan/{job_id}/events")
def scan_events(job_id: str):
    def gen():
        while True:
            s = get_status(job_id)
            yield f"data: {json.dumps(s)}\n\n"
            if s.get("status") in ("done", "error", "unknown"):
                break
            time.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream")
