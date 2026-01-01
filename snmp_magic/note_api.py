from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse

from snmp_magic.auth import require_user
from snmp_magic.store import get_device_note, set_device_note, delete_device_note

router = APIRouter(prefix="/api/devices", tags=["device-notes"])


def _did(ip: str) -> str:
    # Safe DOM id (dots break CSS selectors)
    return ip.replace(".", "-")


@router.get("/{ip}/note")
def api_get_note(
    ip: str,
    as_: str | None = Query(default=None, alias="as"),
    user=Depends(require_user),
):
    note = get_device_note(ip)

    # HTMX lazy-load mode → return HTML fragment
    if as_ == "html":
        did = _did(ip)
        return HTMLResponse(
            f"""
<div class="mt-3">
  <div class="flex items-center justify-between">
    <div class="text-xs font-medium text-gray-700">Note</div>
    <span id="note-indicator-{did}" class="htmx-indicator text-[11px] text-gray-500">
      Saving…
    </span>
  </div>

  <textarea
    id="note-box-{did}"
    class="mt-1 w-full rounded-lg border border-gray-200 bg-gray-50 px-2 py-1 text-xs text-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-200"
    rows="2"
    placeholder="Add a note for this device…"
    name="note"
    hx-put="/api/devices/{ip}/note"
    hx-trigger="keyup changed delay:600ms"
    hx-target="#note-status-{did}"
    hx-swap="innerHTML"
    hx-indicator="#note-indicator-{did}"
  >{note or ""}</textarea>

  <div class="mt-1 flex items-center justify-between">
    <div id="note-status-{did}" class="text-[11px] text-gray-500"></div>

    <button
      class="text-[11px] text-rose-600 hover:underline"
      hx-delete="/api/devices/{ip}/note"
      hx-target="#note-status-{did}"
      hx-swap="innerHTML"
      onclick="document.getElementById('note-box-{did}').value='';"
    >
      Clear
    </button>
  </div>
</div>
"""
        )

    # Default JSON API
    return JSONResponse({"ip": ip, "note": note})


@router.put("/{ip}/note", response_class=HTMLResponse)
def api_put_note(
    ip: str,
    note: str = Form(""),
    user=Depends(require_user),
):
    set_device_note(ip, note)
    return "Saved ✓"


@router.delete("/{ip}/note", response_class=HTMLResponse)
def api_delete_note(ip: str, user=Depends(require_user)):
    delete_device_note(ip)
    return "Cleared ✓"
