# snmp_magic/auth.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Header, status
from fastapi import Depends, HTTPException, Header, Request, status
from typing import Optional
from fastapi import Request
from snmp_magic.store import get_user_by_token, revoke_token

AUTH_COOKIE = "snmp_magic_token"  

@dataclass
class CurrentUser:
    id: int
    username: str
    email: Optional[str]
    is_admin: bool


def _parse_bearer(authorization) -> Optional[str]:
    if not authorization or not isinstance(authorization, str):
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip(), parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def require_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    # 1) API clients
    token = _parse_bearer(authorization)

    # 2) Browser UI (HttpOnly cookie)
    if not token:
        token = request.cookies.get(AUTH_COOKIE)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )

    user = get_user_by_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid/expired token",
        )

    return user


def require_admin(user: CurrentUser = Depends(require_user)) -> CurrentUser:
    if not getattr(user, "is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


def revoke_current_token(authorization: Optional[str], request: Request) -> None:
    token = _parse_bearer(authorization)

    # If no bearer token, try cookie token used by UI
    if not token:
        token = request.cookies.get(AUTH_COOKIE)

    if token:
        revoke_token(token)
