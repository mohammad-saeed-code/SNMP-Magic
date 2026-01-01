# snmp_magic/routes_auth.py
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Header, status, Depends
from pydantic import BaseModel

from snmp_magic.store import verify_user_password, issue_token
from snmp_magic.auth import require_user, revoke_current_token, CurrentUser
from fastapi.responses import JSONResponse
from fastapi import Request
router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginReq(BaseModel):
    username: str
    password: str
    ttl_hours: Optional[int] = 24 * 30  # default 30 days
    label: Optional[str] = "web"


class LoginResp(BaseModel):
    token: str
    token_type: str = "Bearer"


@router.post("/login", response_model=LoginResp)
def login(req: LoginReq):
    user_id = verify_user_password(req.username, req.password)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad username or password",
        )
    token = issue_token(user_id, ttl_hours=req.ttl_hours, label=req.label)
    return LoginResp(token=token)


@router.get("/me")
def me(user: CurrentUser = Depends(require_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
    }


@router.post("/logout")
def logout(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    user: CurrentUser = Depends(require_user),
):
    revoke_current_token(authorization, request)

    resp = JSONResponse({"ok": True})
    # clear cookie in browser
    resp.delete_cookie("snmp_magic_token", path="/")
    return resp
