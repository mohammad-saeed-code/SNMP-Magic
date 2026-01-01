# snmp_magic/store.py
from __future__ import annotations

import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple, Literal

import anyio
from sqlmodel import SQLModel, Field, create_engine, Session, select
from sqlalchemy import Column, JSON, event

# FastAPI guards (import-safe; you can import these dependencies from store.py)
from fastapi import Depends, Header, HTTPException, status

# Optional pysnmp (used for SNMP credential test)
# If you don't want pysnmp dependency here, move SNMP test functions to snmp.py
try:
    from pysnmp.hlapi import (
        SnmpEngine,
        CommunityData,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmHMAC128SHA224AuthProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol,
        usmHMAC384SHA512AuthProtocol,
        usmDESPrivProtocol,
        usm3DESEDEPrivProtocol,
        usmAesCfb128Protocol,
        usmAesCfb192Protocol,
        usmAesCfb256Protocol,
    )
    _PYSNMP_OK = True
except Exception:
    _PYSNMP_OK = False


# =============================================================================
# Password + Token helpers
# =============================================================================

_PBKDF2_ITERS = 210_000
_PBKDF2_ALGO = "sha256"
_SALT_BYTES = 16
_TOKEN_BYTES = 32


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, _PBKDF2_ITERS)


def hash_password_for_storage(password: str) -> Tuple[str, str]:
    """Returns (salt_hex, hash_hex)."""
    salt = secrets.token_bytes(_SALT_BYTES)
    pw_hash = _hash_password(password, salt)
    return salt.hex(), pw_hash.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    computed = _hash_password(password, salt)
    return hmac.compare_digest(computed, expected)


def _new_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# =============================================================================
# Database Models
# =============================================================================

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    username: str = Field(index=True, unique=True)
    email: Optional[str] = Field(default=None, index=True, unique=True)

    password_salt: str
    password_hash: str

    # Role model: admin/user
    is_admin: bool = False

    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None


class AuthToken(SQLModel, table=True):
    """
    Bearer tokens for API auth/sessions.
    Store only a hash of the token (DB compromise doesn't leak active tokens).
    """
    id: Optional[int] = Field(default=None, primary_key=True)

    user_id: int = Field(foreign_key="user.id", index=True)
    token_hash: str = Field(index=True, unique=True)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    label: Optional[str] = None


class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ip: str = Field(index=True, unique=True)

    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None

    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class DeviceSnmpProfile(SQLModel, table=True):
    """
    Device-specific SNMP creds (learned/saved per device).
    This replaces your previous SnmpProfile model name to avoid confusion with global profiles.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True, unique=True)

    version: str = "2c"  # "2c" or "3"
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # v2c
    community: Optional[str] = None

    # v3
    username: Optional[str] = None
    security_level: Optional[str] = None  # "noAuthNoPriv" | "authNoPriv" | "authPriv"
    auth_protocol: Optional[str] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None
    priv_password: Optional[str] = None
    context_name: Optional[str] = None


class GlobalSnmpProfile(SQLModel, table=True):
    """
    Reusable SNMP profiles for scans & testing (NOT tied to devices).
    One of them may be default for scan operations.
    """
    id: Optional[int] = Field(default=None, primary_key=True)

    name: str = Field(index=True, unique=True)
    version: str = "2c"  # "2c" or "3"

    # v2c
    community: Optional[str] = None

    # v3
    username: Optional[str] = None
    security_level: Optional[str] = None
    auth_protocol: Optional[str] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None
    priv_password: Optional[str] = None
    context_name: Optional[str] = None

    is_default: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AppSettings(SQLModel, table=True):
    """
    Single-row application settings, editable live without restart.
    """
    id: int = Field(default=1, primary_key=True)

    # Scan defaults
    snmp_port: int = 161
    snmp_timeout_ms: int = 2000
    snmp_retries: int = 1

    # Discovery/UI defaults
    discovery_workers: int = 128
    ui_scan_time_limit_s: int = 30

    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    started_at: datetime
    finished_at: datetime
    mode: str
    target: Optional[str] = None
    status: str
    result: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))


class Interface(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id")
    if_index: int
    name: str
    alias: Optional[str] = None
    description: Optional[str] = None
    speed: str = "0"
    mac_address: Optional[str] = None
    admin_status: str = "unknown"
    oper_status: str = "unknown"
    vlan: Optional[int] = None


class LldpNeighbor(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    interface_id: int = Field(foreign_key="interface.id")
    remote_sys_name: Optional[str] = None
    remote_port_id: Optional[str] = None
    remote_port_desc: Optional[str] = None

class DeviceTag(SQLModel, table=True):
    """
    User-defined tags for a device (many tags per device).
    Example: "core", "printer", "needs-upgrade", "VIP"
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)

    name: str = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceNote(SQLModel, table=True):
    """
    User-defined note for a device (free-form info).
    Keep single-row-per-device for simplicity.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True, unique=True)

    note: str = ""
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# =============================================================================
# DB Setup
# =============================================================================

DB_URL = os.getenv("SNMP_MAGIC_DB_URL", "sqlite:///snmp_magic.db")
engine = create_engine(DB_URL, echo=False)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        # Don't crash on non-sqlite engines
        pass


def init_db() -> None:
    """
    Create tables and seed a default admin user if it doesn't exist.
    """
    SQLModel.metadata.create_all(engine)
    _ensure_app_settings()
    _ensure_seed_admin()


def _ensure_app_settings() -> None:
    with Session(engine) as s:
        st = s.get(AppSettings, 1)
        if not st:
            s.add(AppSettings(id=1))
            s.commit()


def _ensure_seed_admin() -> None:
    """
    Creates default admin user: snmpmagic / snmpmagic (only if missing).
    """
    with Session(engine) as s:
        u = s.exec(select(User).where(User.username == "snmpmagic")).first()
        if u:
            return
        salt_hex, hash_hex = hash_password_for_storage("snmpmagic")
        s.add(
            User(
                username="snmpmagic",
                email=None,
                password_salt=salt_hex,
                password_hash=hash_hex,
                is_admin=True,
                is_active=True,
                created_at=datetime.utcnow(),
            )
        )
        s.commit()


# =============================================================================
# User Management API
# =============================================================================

def create_user(username: str, password: str, email: Optional[str] = None, *, is_admin: bool = False) -> int:
    salt_hex, hash_hex = hash_password_for_storage(password)
    now = datetime.utcnow()

    with Session(engine) as s:
        if s.exec(select(User).where(User.username == username)).first():
            raise ValueError("username already exists")

        if email and s.exec(select(User).where(User.email == email)).first():
            raise ValueError("email already exists")

        u = User(
            username=username,
            email=email,
            password_salt=salt_hex,
            password_hash=hash_hex,
            is_admin=is_admin,
            is_active=True,
            created_at=now,
        )
        s.add(u)
        s.commit()
        s.refresh(u)
        return int(u.id)


def list_users() -> List[User]:
    with Session(engine) as s:
        return list(s.exec(select(User).order_by(User.username)).all())


def get_user(user_id: int) -> Optional[User]:
    with Session(engine) as s:
        return s.get(User, user_id)


def get_user_by_username(username: str) -> Optional[User]:
    with Session(engine) as s:
        return s.exec(select(User).where(User.username == username)).first()


def _count_admins(s: Session) -> int:
    return len(s.exec(select(User).where(User.is_admin == True, User.is_active == True)).all())


def delete_user_safe(*, requester_id: int, target_user_id: int) -> None:
    """
    Safety rules:
    - Admin-only should be enforced at router layer, but we also keep guardrails here.
    - Can't delete self.
    - Can't delete last active admin.
    """
    with Session(engine) as s:
        requester = s.get(User, requester_id)
        target = s.get(User, target_user_id)

        if not requester or not requester.is_active:
            raise ValueError("invalid requester")
        if not target:
            return

        if requester.id == target.id:
            raise ValueError("cannot delete yourself")

        if target.is_admin and _count_admins(s) <= 1:
            raise ValueError("cannot delete the last admin")

        s.delete(target)
        s.commit()


def set_user_password(*, target_user_id: int, new_password: str) -> None:
    """
    Admin reset OR internal helper.
    """
    salt_hex, hash_hex = hash_password_for_storage(new_password)
    with Session(engine) as s:
        u = s.get(User, target_user_id)
        if not u:
            raise ValueError("user not found")
        u.password_salt = salt_hex
        u.password_hash = hash_hex
        s.add(u)
        s.commit()


def change_own_password(*, user_id: int, old_password: str, new_password: str) -> None:
    with Session(engine) as s:
        u = s.get(User, user_id)
        if not u or not u.is_active:
            raise ValueError("user not found")

        if not verify_password(old_password, u.password_salt, u.password_hash):
            raise ValueError("old password incorrect")

        salt_hex, hash_hex = hash_password_for_storage(new_password)
        u.password_salt = salt_hex
        u.password_hash = hash_hex
        s.add(u)
        s.commit()


def verify_user_password(username: str, password: str) -> Optional[int]:
    with Session(engine) as s:
        u = s.exec(select(User).where(User.username == username)).first()
        if not u or not u.is_active:
            return None

        if not verify_password(password, u.password_salt, u.password_hash):
            return None

        u.last_login_at = datetime.utcnow()
        s.add(u)
        s.commit()
        return int(u.id)


# =============================================================================
# Token auth
# =============================================================================

def issue_token(user_id: int, *, ttl_hours: Optional[int] = 24 * 30, label: Optional[str] = None) -> str:
    token = _new_token()
    token_hash = _hash_token(token)
    now = datetime.utcnow()
    expires = (now + timedelta(hours=ttl_hours)) if ttl_hours else None

    with Session(engine) as s:
        u = s.get(User, user_id)
        if not u or not u.is_active:
            raise ValueError("invalid user")

        t = AuthToken(
            user_id=user_id,
            token_hash=token_hash,
            created_at=now,
            expires_at=expires,
            revoked_at=None,
            label=label,
        )
        s.add(t)
        s.commit()

    return token


def get_user_by_token(token: str) -> Optional[User]:
    th = _hash_token(token)
    now = datetime.utcnow()

    with Session(engine) as s:
        t = s.exec(select(AuthToken).where(AuthToken.token_hash == th)).first()
        if not t or t.revoked_at is not None:
            return None
        if t.expires_at is not None and t.expires_at <= now:
            return None

        u = s.get(User, t.user_id)
        if not u or not u.is_active:
            return None
        return u


def revoke_token(token: str) -> None:
    th = _hash_token(token)
    now = datetime.utcnow()

    with Session(engine) as s:
        t = s.exec(select(AuthToken).where(AuthToken.token_hash == th)).first()
        if not t:
            return
        t.revoked_at = now
        s.add(t)
        s.commit()


# =============================================================================
# FastAPI route guards (Admin-only access)
# =============================================================================

def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip(), parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def current_user(authorization: Optional[str] = Header(default=None)) -> User:
    """
    Dependency that returns the current user or raises 401.
    Uses: Authorization: Bearer <token>
    """
    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")

    u = get_user_by_token(token)
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")
    return u


def require_user(u: User = Depends(current_user)) -> User:
    return u


def require_admin(u: User = Depends(current_user)) -> User:
    if not u.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin required")
    return u


# =============================================================================
# Global AppSettings (scan defaults)
# =============================================================================

def get_app_settings() -> AppSettings:
    with Session(engine) as s:
        st = s.get(AppSettings, 1)
        if not st:
            st = AppSettings(id=1)
            s.add(st)
            s.commit()
            s.refresh(st)
        return st


def update_app_settings(patch: Dict[str, Any]) -> AppSettings:
    """
    patch keys: snmp_port, snmp_timeout_ms, snmp_retries,
                discovery_workers, ui_scan_time_limit_s
    """
    with Session(engine) as s:
        st = s.get(AppSettings, 1)
        if not st:
            st = AppSettings(id=1)
            s.add(st)
            s.commit()
            s.refresh(st)

        for k in ("snmp_port", "snmp_timeout_ms", "snmp_retries", "discovery_workers", "ui_scan_time_limit_s"):
            if k in patch and patch[k] is not None:
                setattr(st, k, int(patch[k]))

        st.updated_at = datetime.utcnow()
        s.add(st)
        s.commit()
        s.refresh(st)
        return st


# =============================================================================
# Global SNMP profiles (reusable)
# =============================================================================

def list_global_snmp_profiles() -> List[GlobalSnmpProfile]:
    with Session(engine) as s:
        return list(s.exec(select(GlobalSnmpProfile).order_by(GlobalSnmpProfile.name)).all())


def get_global_snmp_profile(profile_id: int) -> Optional[GlobalSnmpProfile]:
    with Session(engine) as s:
        return s.get(GlobalSnmpProfile, profile_id)


def create_global_snmp_profile(data: Dict[str, Any]) -> int:
    """
    data requires: name, version
    and corresponding v2c/v3 fields.
    """
    now = datetime.utcnow()
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("profile name required")

    version = str(data.get("version") or "2c").strip()
    if version not in ("2c", "3"):
        raise ValueError("invalid version")

    with Session(engine) as s:
        if s.exec(select(GlobalSnmpProfile).where(GlobalSnmpProfile.name == name)).first():
            raise ValueError("profile name already exists")

        p = GlobalSnmpProfile(name=name, version=version, created_at=now, updated_at=now)

        if version == "2c":
            comm = (data.get("community") or "").strip()
            if not comm:
                raise ValueError("community required for v2c")
            p.community = comm
            # clear v3
            p.username = p.security_level = p.auth_protocol = p.auth_password = None
            p.priv_protocol = p.priv_password = p.context_name = None

        else:
            username = (data.get("username") or "").strip()
            if not username:
                raise ValueError("username required for v3")
            p.username = username
            p.security_level = data.get("security_level") or "noAuthNoPriv"
            p.auth_protocol = data.get("auth_protocol")
            p.auth_password = data.get("auth_password")
            p.priv_protocol = data.get("priv_protocol")
            p.priv_password = data.get("priv_password")
            p.context_name = data.get("context_name")
            p.community = None

        # if requested default
        if bool(data.get("is_default")):
            for other in s.exec(select(GlobalSnmpProfile)).all():
                other.is_default = False
                s.add(other)
            p.is_default = True

        s.add(p)
        s.commit()
        s.refresh(p)
        return int(p.id)


def update_global_snmp_profile(profile_id: int, patch: Dict[str, Any]) -> None:
    now = datetime.utcnow()
    with Session(engine) as s:
        p = s.get(GlobalSnmpProfile, profile_id)
        if not p:
            raise ValueError("profile not found")

        if "name" in patch and patch["name"]:
            name = str(patch["name"]).strip()
            if name != p.name and s.exec(select(GlobalSnmpProfile).where(GlobalSnmpProfile.name == name)).first():
                raise ValueError("profile name already exists")
            p.name = name

        if "version" in patch and patch["version"]:
            ver = str(patch["version"]).strip()
            if ver not in ("2c", "3"):
                raise ValueError("invalid version")
            p.version = ver

        # Apply fields depending on version
        if p.version == "2c":
            if "community" in patch and patch["community"] is not None:
                comm = str(patch["community"]).strip()
                if not comm:
                    raise ValueError("community required for v2c")
                p.community = comm
            # clear v3 fields
            p.username = p.security_level = p.auth_protocol = p.auth_password = None
            p.priv_protocol = p.priv_password = p.context_name = None

        else:
            if "username" in patch and patch["username"] is not None:
                u = str(patch["username"]).strip()
                if not u:
                    raise ValueError("username required for v3")
                p.username = u
            for k in ("security_level", "auth_protocol", "auth_password", "priv_protocol", "priv_password", "context_name"):
                if k in patch:
                    setattr(p, k, patch.get(k))
            p.community = None

        if "is_default" in patch and bool(patch["is_default"]):
            # unset other defaults
            for other in s.exec(select(GlobalSnmpProfile)).all():
                if other.id != p.id:
                    other.is_default = False
                    s.add(other)
            p.is_default = True

        p.updated_at = now
        s.add(p)
        s.commit()


def delete_global_snmp_profile(profile_id: int) -> None:
    with Session(engine) as s:
        p = s.get(GlobalSnmpProfile, profile_id)
        if not p:
            return

        was_default = bool(p.is_default)
        s.delete(p)
        s.commit()

        # If we deleted the default, pick another as default (optional behavior)
        if was_default:
            remaining = s.exec(select(GlobalSnmpProfile).order_by(GlobalSnmpProfile.id)).all()
            if remaining:
                remaining[0].is_default = True
                s.add(remaining[0])
                s.commit()


def get_default_global_snmp_profile() -> Optional[Dict[str, Any]]:
    with Session(engine) as s:
        p = s.exec(select(GlobalSnmpProfile).where(GlobalSnmpProfile.is_default == True)).first()
        if not p:
            return None
        return global_profile_to_dict(p, include_secrets=True)


def global_profile_to_dict(p: GlobalSnmpProfile, *, include_secrets: bool = False) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "id": p.id,
        "name": p.name,
        "version": p.version,
        "is_default": p.is_default,
        "updated_at": p.updated_at.isoformat(),
    }
    if p.version == "2c":
        d["community"] = p.community if include_secrets else None
    else:
        d.update(
            {
                "username": p.username,
                "security_level": p.security_level,
                "auth_protocol": p.auth_protocol,
                "priv_protocol": p.priv_protocol,
                "context_name": p.context_name,
            }
        )
        if include_secrets:
            d["auth_password"] = p.auth_password
            d["priv_password"] = p.priv_password
    return d


# =============================================================================
# Device SNMP profiles (per-device, learned/saved)
# =============================================================================

def upsert_device_snmp_profile(s: Session, ip: str, profile: Dict[str, Any], now: Optional[datetime] = None) -> None:
    now = now or datetime.utcnow()

    dev = s.exec(select(Device).where(Device.ip == ip)).first()
    if not dev:
        dev = Device(ip=ip, first_seen=now, last_seen=now)
        s.add(dev)
        s.commit()
        s.refresh(dev)

    p = s.exec(select(DeviceSnmpProfile).where(DeviceSnmpProfile.device_id == dev.id)).first()
    if not p:
        p = DeviceSnmpProfile(device_id=dev.id)
        s.add(p)

    if "version" in profile and profile["version"]:
        p.version = str(profile["version"])
    p.updated_at = now

    if p.version == "2c":
        if "community" in profile:
            p.community = profile.get("community")
        # clear v3
        p.username = p.security_level = p.auth_protocol = p.auth_password = None
        p.priv_protocol = p.priv_password = p.context_name = None

    elif p.version == "3":
        for k in (
            "username", "security_level",
            "auth_protocol", "auth_password",
            "priv_protocol", "priv_password",
            "context_name",
        ):
            if k in profile:
                setattr(p, k, profile.get(k))
        p.community = None

    s.commit()


def get_device_snmp_profile_by_ip(s: Session, ip: str) -> Optional[Dict[str, Any]]:
    dev = s.exec(select(Device).where(Device.ip == ip)).first()
    if not dev:
        return None

    p = s.exec(select(DeviceSnmpProfile).where(DeviceSnmpProfile.device_id == dev.id)).first()
    if not p:
        return None

    if p.version == "2c":
        if not p.community:
            return None
        return {"version": "2c", "community": p.community}

    if p.version == "3":
        if not p.username:
            return None
        return {
            "version": "3",
            "username": p.username,
            "security_level": p.security_level,
            "auth_protocol": p.auth_protocol,
            "auth_password": p.auth_password,
            "priv_protocol": p.priv_protocol,
            "priv_password": p.priv_password,
            "context_name": p.context_name,
        }

    return None


def save_device_snmp_profile(ip: str, profile: Dict[str, Any]) -> None:
    now = datetime.utcnow()
    with Session(engine) as s:
        upsert_device_snmp_profile(s, ip, profile, now=now)


def load_device_snmp_profile(ip: str) -> Optional[Dict[str, Any]]:
    with Session(engine) as s:
        return get_device_snmp_profile_by_ip(s, ip)


# =============================================================================
# SNMP Credential Test (safe, threaded, timeout, never crash server)
# =============================================================================

_AUTH_MAP = {
    None: None,
    "MD5": usmHMACMD5AuthProtocol if _PYSNMP_OK else None,
    "SHA": usmHMACSHAAuthProtocol if _PYSNMP_OK else None,
    "SHA224": usmHMAC128SHA224AuthProtocol if _PYSNMP_OK else None,
    "SHA256": usmHMAC192SHA256AuthProtocol if _PYSNMP_OK else None,
    "SHA384": usmHMAC256SHA384AuthProtocol if _PYSNMP_OK else None,
    "SHA512": usmHMAC384SHA512AuthProtocol if _PYSNMP_OK else None,
}

_PRIV_MAP = {
    None: None,
    "DES": usmDESPrivProtocol if _PYSNMP_OK else None,
    "3DES": usm3DESEDEPrivProtocol if _PYSNMP_OK else None,
    "AES128": usmAesCfb128Protocol if _PYSNMP_OK else None,
    "AES192": usmAesCfb192Protocol if _PYSNMP_OK else None,
    "AES256": usmAesCfb256Protocol if _PYSNMP_OK else None,
}


def _snmp_get_sysname_sync(
    *,
    target_ip: str,
    port: int,
    timeout_s: float,
    retries: int,
    profile: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Runs in a worker thread. Returns dict {success, sys_name?, error?}
    """
    if not _PYSNMP_OK:
        return {"success": False, "error": "pysnmp not installed/available"}

    try:
        version = str(profile.get("version") or "2c")
        if version not in ("2c", "3"):
            return {"success": False, "error": "invalid profile version"}

        # OID sysName.0
        oid = ObjectIdentity("1.3.6.1.2.1.1.5.0")

        if version == "2c":
            community = profile.get("community")
            if not community:
                return {"success": False, "error": "missing community"}
            auth = CommunityData(community, mpModel=1)  # SNMPv2c
        else:
            username = profile.get("username")
            if not username:
                return {"success": False, "error": "missing v3 username"}
            sec_level = profile.get("security_level") or "noAuthNoPriv"
            auth_proto = _AUTH_MAP.get((profile.get("auth_protocol") or "").upper() or None)
            priv_proto = _PRIV_MAP.get((profile.get("priv_protocol") or "").upper() or None)
            auth_pw = profile.get("auth_password") or None
            priv_pw = profile.get("priv_password") or None

            # pysnmp chooses securityLevel based on presence of auth/priv protocols/passwords
            auth = UsmUserData(
                userName=username,
                authKey=auth_pw,
                privKey=priv_pw,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )

        context_name = profile.get("context_name") or ""

        iterator = getCmd(
            SnmpEngine(),
            auth,
            UdpTransportTarget((target_ip, int(port)), timeout=float(timeout_s), retries=int(retries)),
            ContextData(contextName=context_name),
            ObjectType(oid),
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            return {"success": False, "error": str(errorIndication)}

        if errorStatus:
            return {"success": False, "error": f"{errorStatus.prettyPrint()} at {errorIndex}"}

        # Parse result
        for name, val in varBinds:
            return {"success": True, "sys_name": str(val)}

        return {"success": False, "error": "no response"}

    except Exception as e:
        # Never crash server: return safe error
        return {"success": False, "error": f"exception: {type(e).__name__}: {e}"}


async def snmp_test_sysname(
    *,
    target_ip: str,
    profile: Dict[str, Any],
    port: Optional[int] = None,
    timeout_ms: Optional[int] = None,
    retries: Optional[int] = None,
    hard_timeout_s: float = 5.0,
) -> Dict[str, Any]:
    """
    Async wrapper: runs SNMP GET in worker thread with hard timeout.
    Safe: never raises; returns {success, sys_name?} or {success:false, error}.
    """
    try:
        st = get_app_settings()
        port = int(port or st.snmp_port)
        timeout_ms = int(timeout_ms or st.snmp_timeout_ms)
        retries = int(retries if retries is not None else st.snmp_retries)
        timeout_s = max(0.2, float(timeout_ms) / 1000.0)

        with anyio.fail_after(hard_timeout_s):
            return await anyio.to_thread.run_sync(
                _snmp_get_sysname_sync,
                target_ip=target_ip,
                port=port,
                timeout_s=timeout_s,
                retries=retries,
                profile=profile,
            )
    except TimeoutError:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": f"exception: {type(e).__name__}: {e}"}


# =============================================================================
# Scan Saving Logic (kept compatible with your existing payloads)
# =============================================================================

def save_scan(payload: Dict[str, Any], mode: str, target: str, status: str = "ok") -> int:
    now = datetime.utcnow()

    with Session(engine) as s:
        sc = Scan(
            started_at=now,
            finished_at=now,
            mode=mode,
            target=target,
            status=status,
            result=payload,
        )
        s.add(sc)
        s.commit()
        s.refresh(sc)

        if mode == "single" and status == "ok":
            host_data = payload.get("host") or {}
            _upsert_host_detailed(s, host_data, now)

        elif mode == "discovery" and status == "ok":
            hosts = payload.get("hosts", [])
            for h in hosts:
                _upsert_host_basic(s, h, now)

        return int(sc.id)


def _upsert_host_basic(s: Session, data: dict, now: datetime):
    ip = data.get("ip")
    if not ip:
        return

    dev = s.exec(select(Device).where(Device.ip == ip)).first()
    if not dev:
        dev = Device(ip=ip, first_seen=now)
        s.add(dev)

    dev.last_seen = now
    if data.get("sys_name"):
        dev.sys_name = data.get("sys_name")
    if data.get("sys_descr"):
        dev.sys_descr = data.get("sys_descr")

    s.commit()


def _upsert_host_detailed(s: Session, data: dict, now: datetime):
    ip = data.get("target")
    if not ip:
        return

    dev = s.exec(select(Device).where(Device.ip == ip)).first()
    if not dev:
        dev = Device(ip=ip, first_seen=now)
        s.add(dev)

    dev.last_seen = now
    dev.sys_name = data.get("sys_name")
    dev.sys_descr = data.get("sys_descr")
    s.commit()
    s.refresh(dev)

    # Optional auto-save SNMP creds from scan payload
    snmp_block = data.get("snmp")
    if isinstance(snmp_block, dict) and snmp_block:
        upsert_device_snmp_profile(s, ip, snmp_block, now=now)

    # Replace strategy: delete old interfaces
    existing_ifs = s.exec(select(Interface).where(Interface.device_id == dev.id)).all()
    for i in existing_ifs:
        s.delete(i)
    s.commit()

    raw_ifaces = data.get("interfaces", [])
    raw_lldp = data.get("lldp", {})

    for row in raw_ifaces:
        if_obj = Interface(
            device_id=dev.id,
            if_index=row.get("ifIndex", 0),
            name=row.get("name") or "unknown",
            alias=row.get("alias"),
            speed=str(row.get("speed", "0")),
            mac_address=row.get("mac"),
            admin_status=str(row.get("admin", "unknown")),
            oper_status=str(row.get("oper", "unknown")),
            vlan=row.get("pvid"),
        )
        s.add(if_obj)
        s.commit()
        s.refresh(if_obj)

        neighbors = raw_lldp.get(if_obj.name) or raw_lldp.get(str(if_obj.if_index)) or []
        for n in neighbors:
            s.add(
                LldpNeighbor(
                    interface_id=if_obj.id,
                    remote_sys_name=n.get("sysName"),
                    remote_port_id=n.get("portId"),
                    remote_port_desc=n.get("portDesc"),
                )
            )

    s.commit()



#====================================
#===========Add tag/note helpers=====
#====================================

def list_device_tags(ip: str) -> List[str]:
    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            return []
        tags = s.exec(select(DeviceTag).where(DeviceTag.device_id == dev.id).order_by(DeviceTag.name)).all()
        return [t.name for t in tags]


def add_device_tag(ip: str, tag: str) -> None:
    tag = (tag or "").strip()
    if not tag:
        raise ValueError("tag required")
    if len(tag) > 32:
        raise ValueError("tag too long (max 32)")

    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            # create device entry if missing (consistent with upsert behavior)
            now = datetime.utcnow()
            dev = Device(ip=ip, first_seen=now, last_seen=now)
            s.add(dev)
            s.commit()
            s.refresh(dev)

        exists = s.exec(
            select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.name == tag)
        ).first()
        if exists:
            return

        s.add(DeviceTag(device_id=dev.id, name=tag))
        s.commit()


def remove_device_tag(ip: str, tag: str) -> None:
    tag = (tag or "").strip()
    if not tag:
        return

    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            return

        row = s.exec(
            select(DeviceTag).where(DeviceTag.device_id == dev.id, DeviceTag.name == tag)
        ).first()
        if not row:
            return

        s.delete(row)
        s.commit()


def get_device_note(ip: str) -> str:
    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            return ""
        n = s.exec(select(DeviceNote).where(DeviceNote.device_id == dev.id)).first()
        return n.note if n else ""


def set_device_note(ip: str, note: str) -> None:
    note = note or ""
    if len(note) > 2000:
        raise ValueError("note too long (max 2000 chars)")

    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            now = datetime.utcnow()
            dev = Device(ip=ip, first_seen=now, last_seen=now)
            s.add(dev)
            s.commit()
            s.refresh(dev)

        row = s.exec(select(DeviceNote).where(DeviceNote.device_id == dev.id)).first()
        if not row:
            row = DeviceNote(device_id=dev.id, note=note, updated_at=datetime.utcnow())
            s.add(row)
        else:
            row.note = note
            row.updated_at = datetime.utcnow()
            s.add(row)

        s.commit()

        
def delete_device_note(ip: str) -> None:
    with Session(engine) as s:
        dev = s.exec(select(Device).where(Device.ip == ip)).first()
        if not dev:
            return
        note = s.exec(select(DeviceNote).where(DeviceNote.device_id == dev.id)).first()
        if note:
            s.delete(note)
            s.commit()