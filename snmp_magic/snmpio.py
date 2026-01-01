# snmp_magic/snmpio.py
import logging
from typing import Generator, Tuple, Optional, Any

log = logging.getLogger(__name__)

# Legacy-only mode (sync HLAPI)
_PYSNMP_OK = False

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd, nextCmd,
        UsmUserData, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmAesCfb128Protocol, usmDESPrivProtocol, usmNoAuthProtocol, usmNoPrivProtocol
    )
    _PYSNMP_OK = True
except Exception as e:
    log.warning(
        "Legacy PySNMP HLAPI not available (%s). "
        "Install legacy pysnmp (recommended: pysnmp-lextudio==5.0.34). "
        "SNMP will be disabled but server will run.",
        e
    )
    _PYSNMP_OK = False

    # Dummy types so imports elsewhere don’t crash
    SnmpEngine = object
    CommunityData = object
    UdpTransportTarget = object
    ContextData = object
    ObjectType = object
    ObjectIdentity = object
    UsmUserData = object


def transport(host: str, port: int = 161, timeout: int = 1, retries: int = 1):
    if not _PYSNMP_OK:
        return None
    return UdpTransportTarget((host, port), timeout=float(timeout), retries=int(retries))


def _auth(community_or_v3):
    if not _PYSNMP_OK:
        return None

    # v1/v2c: ("1"|"2c", "public") OR just "public"
    if isinstance(community_or_v3, tuple) and len(community_or_v3) == 2:
        version, community = community_or_v3
        version = (version or "2c").lower()
        if version == "1":
            return CommunityData(community, mpModel=0)
        return CommunityData(community, mpModel=1)

    if isinstance(community_or_v3, str):
        return CommunityData(community_or_v3, mpModel=1)

    # v3: dict
    v3 = dict(community_or_v3 or {})
    user = v3.get("user", "")
    auth_proto = (v3.get("auth_proto") or "NONE").upper()
    priv_proto = (v3.get("priv_proto") or "NONE").upper()
    auth_key = v3.get("auth_key") or None
    priv_key = v3.get("priv_key") or None

    auth_p = {
        "MD5": usmHMACMD5AuthProtocol,
        "SHA": usmHMACSHAAuthProtocol,
        "NONE": usmNoAuthProtocol,
    }.get(auth_proto, usmNoAuthProtocol)

    priv_p = {
        "AES": usmAesCfb128Protocol,
        "DES": usmDESPrivProtocol,
        "NONE": usmNoPrivProtocol,
    }.get(priv_proto, usmNoPrivProtocol)

    # Build user data by security level
    if auth_p is usmNoAuthProtocol:
        return UsmUserData(user)

    if priv_p is usmNoPrivProtocol:
        return UsmUserData(user, authKey=auth_key, authProtocol=auth_p)

    return UsmUserData(user, authKey=auth_key, authProtocol=auth_p, privKey=priv_key, privProtocol=priv_p)


def snmp_get(target, community_or_v3, oid: str, timeout: int, retries: int) -> Optional[Any]:
    """
    Old behavior: errors don’t crash the scan, just return None.
    """
    if not _PYSNMP_OK or target is None:
        return None

    try:
        it = getCmd(
            SnmpEngine(),
            _auth(community_or_v3),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        errInd, errStat, errIdx, varBinds = next(it)

        if errInd or errStat or not varBinds:
            return None

        return varBinds[0][1]

    except Exception as e:
        log.debug("SNMP GET failed (oid=%s target=%s): %s", oid, target, e)
        return None


def snmp_walk(target, community_or_v3, oid: str, timeout: int, retries: int) -> Generator[Tuple[str, Any], None, None]:
    """
    Old behavior: yield nothing on errors.
    """
    if not _PYSNMP_OK or target is None:
        return
        yield  # generator form

    try:
        for (errInd, errStat, errIdx, varBinds) in nextCmd(
            SnmpEngine(),
            _auth(community_or_v3),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            ignoreNonIncreasingOid=True,
        ):
            if errInd or errStat:
                return
            for vb in varBinds:
                yield str(vb[0]), vb[1]

    except Exception as e:
        log.debug("SNMP WALK failed (oid=%s target=%s): %s", oid, target, e)
        return
