# SNMP Magic 🧙‍♂️📡

> A self-hosted network discovery and documentation tool powered by SNMP.

SNMP Magic scans your network, pulls device data via SNMP, and presents it in a clean web dashboard — no heavyweight NMS required. Built for home labs, small environments, and anyone who wants quick, structured visibility into their network.

---

## Features

- 🔎 **Network Discovery** — Scan IP addresses, ranges, or CIDR blocks and automatically discover SNMP-enabled devices
- 📡 **Device Inspection** — Query sysName, interfaces, VLANs, LLDP neighbors, MAC/endpoint tables, and more
- 🗺️ **Topology View** — Interactive D3.js network map with device-type filtering, pin/unpin, and PNG export
- 📝 **Device Notes** — Add and auto-save per-device documentation directly from the dashboard
- 🔁 **Scheduled Scans** — Define recurring discovery jobs to keep your inventory current
- 📊 **XLSX Export** — Export device inventory to Excel with one click
- 🔐 **Auth-Protected UI** — Cookie/session-based login; the dashboard is not exposed by default
- 🪟 **Windows EXE** — Ships as a self-contained `.exe` via PyInstaller; no Python install needed on the target machine

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.10+) |
| Database | SQLite via SQLModel |
| Templates | Jinja2 + HTMX |
| Visualization | D3.js |
| SNMP | pysnmp (v1 / v2c / v3) |
| Packaging | PyInstaller (Windows, onedir) |

---

## Getting Started

### Requirements

- Python **3.10+**
- Windows, macOS, or Linux

### Install

```bash
git clone https://github.com/mohammad-saeed-code/SNMP-Magic.git
cd SNMP-Magic
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

---


## Windows Executable

A pre-built `.exe` can be generated with PyInstaller:

```bat
build.bat
```

See `BUILD_README.md` for full packaging instructions. The resulting executable launches a local server and opens the UI in your default browser automatically — no Python or configuration needed on the target machine.

---

## SNMP Support

| Version | Support |
|---------|---------|
| v1 | ✅ |
| v2c | ✅ |
| v3 (noAuthNoPriv / authNoPriv / authPriv) | ✅ |

