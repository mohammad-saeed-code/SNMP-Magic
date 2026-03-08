# snmp_magic/device_classify.py
"""
Classify a network device into a type + assign an icon based on:
  - sysDescr  (most informative — contains OS/vendor/model strings)
  - sysName   (hostname hints like "sw-", "ap-", "printer-")
  - MAC OUI   (vendor from first 3 bytes)

Returns a DeviceClass with:
  device_type : str   short machine-readable type
  label       : str   human-readable label
  icon        : str   single emoji for UI display
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class DeviceClass:
    device_type: str    # e.g. "switch", "router", "printer"
    label:       str    # e.g. "Network Switch"
    icon:        str    # e.g. "🔀"


# ── Classification table ──────────────────────────────────────────────────
# Each entry: (device_type, label, icon, [sysDescr patterns], [sysName patterns])
# Checked in order — first match wins.

_RULES: list[tuple] = [
    # ── Network infrastructure ───────────────────────────────────────────
    (
        "router", "Router", "🌐",
        [r"cisco ios", r"junos", r"mikrotik routeros", r"routeros",
         r"vyos", r"openwrt", r"ddwrt", r"pfsense", r"opnsense",
         r"gateway", r"broadband router", r"dsl router"],
        [r"^gw[\-_]", r"^router", r"^rtr", r"^fw[\-_]", r"^firewall"],
    ),
    (
        "switch", "Network Switch", "🔀",
        [r"cisco catalyst", r"cisco nexus", r"ios.*switch",
         r"juniper.*ex\d", r"hp.*procurve", r"hewlett.packard.*switch",
         r"aruba.*switch", r"extreme.*switch", r"dell.*powerconnect",
         r"netgear.*switch", r"d-link.*switch", r"layer.?2", r"layer.?3",
         r"switching", r"^ex\d{4}", r"catalyst \d{4}"],
        [r"^sw[\-_]", r"^switch", r"^csw", r"^dsw", r"^access[\-_]sw"],
    ),
    (
        "firewall", "Firewall", "🛡️",
        [r"palo alto", r"fortinet", r"fortigate", r"checkpoint",
         r"sonicwall", r"cisco asa", r"cisco firepower",
         r"juniper srx", r"pfsense", r"opnsense", r"watchguard",
         r"barracuda.*firewall"],
        [r"^fw[\-_]", r"^firewall", r"^asa[\-_]", r"^palo[\-_]"],
    ),
    (
        "wireless_ap", "Wireless AP", "📡",
        [r"cisco.*aironet", r"cisco.*air-", r"aruba.*ap",
         r"ruckus", r"ubiquiti", r"unifi.*ap", r"aerohive",
         r"meraki.*ap", r"access point", r"802\.11", r"wifi.*ap",
         r"wireless.*ap"],
        [r"^ap[\-_]", r"^wap[\-_]", r"^wifi[\-_]", r"^wireless"],
    ),
    (
        "load_balancer", "Load Balancer", "⚖️",
        [r"f5.*big.?ip", r"a10.*thunder", r"citrix.*netscaler",
         r"haproxy", r"nginx.*plus", r"kemp.*loadmaster"],
        [r"^lb[\-_]", r"^vip[\-_]"],
    ),

    # ── Servers ──────────────────────────────────────────────────────────
    (
        "linux_server", "Linux Server", "🐧",
        [r"linux", r"ubuntu", r"debian", r"centos", r"red hat",
         r"fedora", r"suse", r"arch linux", r"alpine",
         r"raspbian", r"raspberry pi"],
        [r"^srv[\-_].*lin", r"^linux"],
    ),
    (
        "windows_server", "Windows Server", "🪟",
        [r"windows server", r"windows.*server", r"microsoft.*server",
         r"win32.*server", r"windows nt.*server"],
        [r"^srv[\-_].*win", r"^dc[\-_]", r"^domain.?controller"],
    ),
    (
        "windows", "Windows PC", "🖥️",
        [r"windows 10", r"windows 11", r"windows 7", r"windows 8",
         r"windows xp", r"windows vista", r"microsoft windows"],
        [r"^desktop[\-_]", r"^pc[\-_]", r"^workstation"],
    ),
    (
        "macos", "macOS Device", "🍎",
        [r"mac os x", r"macos", r"darwin"],
        [r"^macbook", r"^imac", r"^mac[\-_]"],
    ),
    (
        "vmware", "VMware Host", "☁️",
        [r"vmware esxi", r"vmware esx", r"vsphere", r"vcenter"],
        [r"^esxi[\-_]", r"^vmhost[\-_]", r"^vsphere"],
    ),
    (
        "hypervisor", "Hypervisor / VM Host", "☁️",
        [r"hyper-v", r"proxmox", r"xen server", r"kvm.*hypervisor"],
        [r"^hv[\-_]", r"^proxmox", r"^xen[\-_]"],
    ),
    (
        "nas", "NAS / Storage", "💾",
        [r"synology", r"qnap", r"freenas", r"truenas", r"netapp",
         r"dell.*equallogic", r"emc.*vnx", r"buffalo.*nas",
         r"western digital.*nas", r"wd.*nas"],
        [r"^nas[\-_]", r"^san[\-_]", r"^storage[\-_]"],
    ),

    # ── Printers / Peripherals ───────────────────────────────────────────
    (
        "printer", "Printer", "🖨️",
        [r"hp.*laserjet", r"hp.*officejet", r"hp.*deskjet",
         r"hp ethernet multi-environment", r"hp.*jetdirect",
         r"canon.*printer", r"canon.*imagerunner", r"epson.*printer",
         r"ricoh", r"xerox", r"lexmark", r"brother.*hl",
         r"konica.*minolta", r"kyocera", r"sharp.*copier",
         r"jetdirect", r"printer", r"print server"],
        [r"^printer", r"^prn[\-_]", r"^mfp[\-_]", r"^copier",
         r"^hp[0-9a-f]{6}", r"^npi[0-9a-f]"],
    ),
    (
        "ups", "UPS", "🔋",
        [r"apc.*ups", r"eaton.*ups", r"schneider.*ups",
         r"powerware", r"liebert", r"vertiv.*ups",
         r"uninterruptible", r"\bups\b"],
        [r"^ups[\-_]", r"^pdu[\-_]"],
    ),
    (
        "camera", "IP Camera / NVR", "📷",
        [r"hikvision", r"dahua", r"axis.*camera", r"bosch.*camera",
         r"hanwha", r"vivotek", r"nvr", r"dvr", r"ip.*camera"],
        [r"^cam[\-_]", r"^nvr[\-_]", r"^dvr[\-_]"],
    ),
    (
        "voip", "VoIP Device", "📞",
        [r"cisco.*ip phone", r"polycom", r"avaya", r"snom",
         r"yealink", r"grandstream", r"asterisk", r"freepbx",
         r"voip", r"sip.*phone"],
        [r"^phone[\-_]", r"^voip[\-_]", r"^pbx[\-_]"],
    ),

    # ── IoT / Embedded ───────────────────────────────────────────────────
    (
        "raspberry_pi", "Raspberry Pi", "🍓",
        [r"raspberry pi", r"raspbian"],
        [r"^rpi[\-_]", r"^raspi[\-_]", r"^raspberry"],
    ),
    (
        "iot", "IoT Device", "📟",
        [r"esp32", r"esp8266", r"arduino", r"home.?assistant",
         r"smartthings", r"zigbee", r"z-wave", r"tasmota"],
        [r"^iot[\-_]", r"^sensor[\-_]", r"^smart[\-_]"],
    ),
]

# OUI → type hint  (supplements sysDescr when it's empty)
_OUI_HINTS: dict[str, str] = {
    "00:50:56": "vmware",  "00:0c:29": "vmware",  "52:54:00": "hypervisor",
    "00:15:5d": "windows", "b8:27:eb": "raspberry_pi",
    "dc:a6:32": "raspberry_pi", "e4:5f:01": "raspberry_pi",
    "ac:e2:d3": "printer", "3c:d9:2b": "printer",
}

_UNKNOWN = DeviceClass("unknown", "Unknown Device", "❓")


def classify(
    sys_descr:  Optional[str] = None,
    sys_name:   Optional[str] = None,
    mac:        Optional[str] = None,
) -> DeviceClass:
    """Return the best DeviceClass for this device."""

    descr = (sys_descr or "").lower().strip()
    name  = (sys_name  or "").lower().strip()

    for device_type, label, icon, descr_pats, name_pats in _RULES:
        for pat in descr_pats:
            if descr and re.search(pat, descr):
                return DeviceClass(device_type, label, icon)
        for pat in name_pats:
            if name and re.search(pat, name):
                return DeviceClass(device_type, label, icon)

    # OUI fallback
    if mac:
        prefix = mac.lower().replace("-", ":")[:8]
        hint = _OUI_HINTS.get(prefix)
        if hint:
            for device_type, label, icon, _, _ in _RULES:
                if device_type == hint:
                    return DeviceClass(device_type, label, icon)

    # If we have *some* sysDescr but nothing matched, at least call it a server
    if descr and len(descr) > 10:
        return DeviceClass("server", "Server / Appliance", "🖥️")

    return _UNKNOWN