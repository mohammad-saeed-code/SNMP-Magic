# snmp_magic/routes_settings.py
from __future__ import annotations

import html
from typing import Optional, Dict, Any

import anyio
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from snmp_magic.auth import require_user, require_admin
from snmp_magic import store
from snmp_magic.ui_env import templates

# ✅ IMPORTANT: use the shared templates configured in server.py (frozen-safe paths)
from server import templates  # if your app entrypoint is server.py at project root

router = APIRouter(prefix="/ui/settings", tags=["ui-settings"])


# ----------------------------
# Helpers
# ----------------------------

def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def _flash(request: Request, kind: str, message: str) -> HTMLResponse:
    """
    Returns a small HTML partial for feedback.
    kind: "success" | "error" | "info"
    """
    return templates.TemplateResponse(
        "settings/partials/flash.html",
        {"request": request, "kind": kind, "message": message},
    )


def _safe_err(e: Exception) -> str:
    # Keep errors user-friendly; still log server-side in your app if you want
    msg = str(e) or e.__class__.__name__
    return msg


@router.get("/flash", response_class=HTMLResponse)
def flash_partial(request: Request, kind: str = "info", msg: str = ""):
    return templates.TemplateResponse(
        "settings/partials/flash.html",
        {"request": request, "kind": kind, "message": msg},
    )
# ----------------------------
# Settings shell
# ----------------------------

@router.get("", response_class=HTMLResponse)
def settings_home(request: Request, user=Depends(require_user)):
    # We render the shell and default to "password" tab (always allowed)
    return templates.TemplateResponse(
        "settings/index.html",
        {"request": request, "user": user, "active": "settings"},
    )


# ----------------------------
# Tabs (partials)
# ----------------------------

@router.get("/tab/password", response_class=HTMLResponse)
def tab_password(request: Request, user=Depends(require_user)):
    return templates.TemplateResponse(
        "settings/tabs/password.html",
        {"request": request, "user": user},
    )


@router.get("/tab/users", response_class=HTMLResponse)
def tab_users(request: Request, user=Depends(require_admin)):
    users = store.list_users()
    return templates.TemplateResponse(
        "settings/tabs/users.html",
        {"request": request, "user": user, "users": users},
    )


@router.get("/tab/snmp", response_class=HTMLResponse)
def tab_snmp_profiles(request: Request, user=Depends(require_admin)):
    profiles = store.list_global_snmp_profiles()
    return templates.TemplateResponse(
        "settings/tabs/snmp.html",
        {"request": request, "user": user, "profiles": profiles},
    )


@router.get("/tab/defaults", response_class=HTMLResponse)
def tab_defaults(request: Request, user=Depends(require_admin)):
    st = store.get_app_settings()
    return templates.TemplateResponse(
        "settings/tabs/defaults.html",
        {"request": request, "user": user, "st": st},
    )


@router.get("/tab/test", response_class=HTMLResponse)
def tab_snmp_test(request: Request, user=Depends(require_user)):
    # Allow any logged-in user to test, or change to require_admin if you prefer.
    profiles = store.list_global_snmp_profiles()
    st = store.get_app_settings()
    return templates.TemplateResponse(
        "settings/tabs/test.html",
        {"request": request, "user": user, "profiles": profiles, "st": st},
    )


# ----------------------------
# User management (admin)
# ----------------------------

@router.post("/users/add", response_class=HTMLResponse)
def users_add(
    request: Request,
    user=Depends(require_admin),
    username: str = Form(...),
    password: str = Form(...),
    email: Optional[str] = Form(None),
    is_admin: Optional[str] = Form(None),  # checkbox -> "on"
):
    try:
        store.create_user(
            username=username.strip(),
            password=password,
            email=(email.strip() if email else None),
            is_admin=bool(is_admin),
        )
        users = store.list_users()
        # Return updated list tab + flash (HTMX swaps both)
        resp = templates.TemplateResponse(
            "settings/tabs/users.html",
            {"request": request, "user": user, "users": users},
        )
        resp.headers["HX-Trigger"] = "flash:success:User created"
        return resp
    except Exception as e:
        users = store.list_users()
        resp = templates.TemplateResponse(
            "settings/tabs/users.html",
            {"request": request, "user": user, "users": users, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


@router.post("/users/{target_user_id}/reset-password", response_class=HTMLResponse)
def users_reset_password(
    request: Request,
    target_user_id: int,
    user=Depends(require_admin),
    new_password: str = Form(...),
):
    try:
        store.set_user_password(target_user_id=target_user_id, new_password=new_password)
        users = store.list_users()
        resp = templates.TemplateResponse(
            "settings/tabs/users.html",
            {"request": request, "user": user, "users": users},
        )
        resp.headers["HX-Trigger"] = "flash:success:Password reset"
        return resp
    except Exception as e:
        users = store.list_users()
        resp = templates.TemplateResponse(
            "settings/tabs/users.html",
            {"request": request, "user": user, "users": users, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


@router.delete("/users/{target_user_id}", response_class=HTMLResponse)
def users_delete(
    request: Request,
    target_user_id: int,
    user=Depends(require_admin),
):
    try:
        store.delete_user_safe(requester_id=user.id, target_user_id=target_user_id)
        users = store.list_users()
        resp = templates.TemplateResponse(
            "settings/tabs/users.html",
            {"request": request, "user": user, "users": users},
        )
        resp.headers["HX-Trigger"] = "flash:success:User deleted"
        return resp
    except Exception as e:
        users = store.list_users()
        resp = templates.TemplateResponse(
            "settings/tabs/users.html",
            {"request": request, "user": user, "users": users, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


# ----------------------------
# Password (self)
# ----------------------------

@router.post("/me/change-password", response_class=HTMLResponse)
def me_change_password(
    request: Request,
    user=Depends(require_user),
    old_password: str = Form(...),
    new_password: str = Form(...),
):
    try:
        store.change_own_password(user_id=user.id, old_password=old_password, new_password=new_password)
        resp = templates.TemplateResponse(
            "settings/tabs/password.html",
            {"request": request, "user": user, "ok": "Password updated"},
        )
        resp.headers["HX-Trigger"] = "flash:success:Password updated"
        return resp
    except Exception as e:
        resp = templates.TemplateResponse(
            "settings/tabs/password.html",
            {"request": request, "user": user, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


# ----------------------------
# Global SNMP profiles (admin)
# ----------------------------

@router.post("/snmp/add", response_class=HTMLResponse)
def snmp_add(
    request: Request,
    user=Depends(require_admin),
    name: str = Form(...),
    version: str = Form("2c"),
    community: Optional[str] = Form(None),
    username: Optional[str] = Form(None),
    security_level: Optional[str] = Form(None),
    auth_protocol: Optional[str] = Form(None),
    auth_password: Optional[str] = Form(None),
    priv_protocol: Optional[str] = Form(None),
    priv_password: Optional[str] = Form(None),
    context_name: Optional[str] = Form(None),
    is_default: Optional[str] = Form(None),
):
    try:
        data: Dict[str, Any] = {
            "name": name.strip(),
            "version": version.strip(),
            "community": (community or None),
            "username": (username or None),
            "security_level": (security_level or None),
            "auth_protocol": (auth_protocol or None),
            "auth_password": (auth_password or None),
            "priv_protocol": (priv_protocol or None),
            "priv_password": (priv_password or None),
            "context_name": (context_name or None),
            "is_default": bool(is_default),
        }
        store.create_global_snmp_profile(data)
        profiles = store.list_global_snmp_profiles()
        resp = templates.TemplateResponse(
            "settings/tabs/snmp.html",
            {"request": request, "user": user, "profiles": profiles},
        )
        resp.headers["HX-Trigger"] = "flash:success:SNMP profile created"
        return resp
    except Exception as e:
        profiles = store.list_global_snmp_profiles()
        resp = templates.TemplateResponse(
            "settings/tabs/snmp.html",
            {"request": request, "user": user, "profiles": profiles, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


@router.post("/snmp/{profile_id}/make-default", response_class=HTMLResponse)
def snmp_make_default(request: Request, profile_id: int, user=Depends(require_admin)):
    try:
        store.update_global_snmp_profile(profile_id, {"is_default": True})
        profiles = store.list_global_snmp_profiles()
        resp = templates.TemplateResponse(
            "settings/tabs/snmp.html",
            {"request": request, "user": user, "profiles": profiles},
        )
        resp.headers["HX-Trigger"] = "flash:success:Default SNMP profile updated"
        return resp
    except Exception as e:
        profiles = store.list_global_snmp_profiles()
        resp = templates.TemplateResponse(
            "settings/tabs/snmp.html",
            {"request": request, "user": user, "profiles": profiles, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


@router.delete("/snmp/{profile_id}", response_class=HTMLResponse)
def snmp_delete(request: Request, profile_id: int, user=Depends(require_admin)):
    try:
        store.delete_global_snmp_profile(profile_id)
        profiles = store.list_global_snmp_profiles()
        resp = templates.TemplateResponse(
            "settings/tabs/snmp.html",
            {"request": request, "user": user, "profiles": profiles},
        )
        resp.headers["HX-Trigger"] = "flash:success:SNMP profile deleted"
        return resp
    except Exception as e:
        profiles = store.list_global_snmp_profiles()
        resp = templates.TemplateResponse(
            "settings/tabs/snmp.html",
            {"request": request, "user": user, "profiles": profiles, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


# ----------------------------
# Defaults (admin)
# ----------------------------

@router.post("/defaults/save", response_class=HTMLResponse)
def defaults_save(
    request: Request,
    user=Depends(require_admin),
    snmp_port: int = Form(...),
    snmp_timeout_ms: int = Form(...),
    snmp_retries: int = Form(...),
    discovery_workers: int = Form(...),
    ui_scan_time_limit_s: int = Form(...),
):
    try:
        st = store.update_app_settings(
            {
                "snmp_port": snmp_port,
                "snmp_timeout_ms": snmp_timeout_ms,
                "snmp_retries": snmp_retries,
                "discovery_workers": discovery_workers,
                "ui_scan_time_limit_s": ui_scan_time_limit_s,
            }
        )
        resp = templates.TemplateResponse(
            "settings/tabs/defaults.html",
            {"request": request, "user": user, "st": st, "ok": "Saved"},
        )
        resp.headers["HX-Trigger"] = "flash:success:Defaults saved"
        return resp
    except Exception as e:
        st = store.get_app_settings()
        resp = templates.TemplateResponse(
            "settings/tabs/defaults.html",
            {"request": request, "user": user, "st": st, "error": _safe_err(e)},
        )
        resp.headers["HX-Trigger"] = f"flash:error:{html.escape(_safe_err(e))}"
        return resp


# ----------------------------
# SNMP credential test (user)
# ----------------------------
# IMPORTANT: Plug in YOUR existing SNMP test logic here.
# This wrapper guarantees:
# - thread offload (no event loop block)
# - hard timeout
# - never raises (returns structured result)
#
# Replace `_snmp_test_sync()` body with a call into your existing SNMP code.
# ----------------------------

def _snmp_test_sync(target_ip: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synchronous function executed in a worker thread.
    REPLACE THIS with your existing SNMP logic.

    Expected return:
      {"success": True, "sys_name": "..."} or {"success": False, "error": "..."}
    """
    # Example placeholder (force you to wire the real one):
    return {"success": False, "error": "SNMP test not wired: connect _snmp_test_sync() to your SNMP code"}


@router.post("/test/run", response_class=HTMLResponse)
async def snmp_test_run(
    request: Request,
    user=Depends(require_user),
    target_ip: str = Form(...),
    profile_id: Optional[int] = Form(None),
    community: Optional[str] = Form(None),
):
    """
    Supports either:
    - pick a saved global profile (profile_id)
    - or ad-hoc v2c community string (community)
    """
    profiles = store.list_global_snmp_profiles()
    st = store.get_app_settings()

    # Build a profile dict
    prof: Dict[str, Any]
    if profile_id:
        p = store.get_global_snmp_profile(int(profile_id))
        if not p:
            return templates.TemplateResponse(
                "settings/tabs/test.html",
                {"request": request, "user": user, "profiles": profiles, "st": st, "error": "Profile not found"},
            )
        prof = store.global_profile_to_dict(p, include_secrets=True)
    else:
        comm = (community or "").strip()
        if not comm:
            return templates.TemplateResponse(
                "settings/tabs/test.html",
                {"request": request, "user": user, "profiles": profiles, "st": st, "error": "Provide profile or community"},
            )
        prof = {"version": "2c", "community": comm}

    # Run in background thread with hard timeout
    result: Dict[str, Any]
    try:
        with anyio.fail_after(5.0):
            result = await anyio.to_thread.run_sync(_snmp_test_sync, target_ip.strip(), prof)
    except TimeoutError:
        result = {"success": False, "error": "timeout"}
    except Exception as e:
        result = {"success": False, "error": f"exception: {_safe_err(e)}"}

    return templates.TemplateResponse(
        "settings/tabs/test.html",
        {
            "request": request,
            "user": user,
            "profiles": profiles,
            "st": st,
            "test_result": result,
            "target_ip": target_ip.strip(),
        },
    )
