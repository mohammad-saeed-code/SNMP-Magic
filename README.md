# SNMP Magic 🧙‍♂️📡

**SNMP Magic** is a lightweight web app for **discovering and documenting SNMP-enabled devices** on your network.  
It’s built with **FastAPI** and a simple UI to scan targets, view results, and add device notes—ideal for lab work, small environments, or quick SOC-style visibility.

---

## Highlights

- 🔎 Scan IPs / ranges and discover devices
- 📡 Query SNMP data and display it in a clean dashboard
- 📝 Add per-device notes (quick documentation)
- 🔐 Authentication (dashboard not exposed by default)
- 🪶 Lightweight and self-hosted (no heavy NMS stack)
- 🪟 Can be packaged as a Windows `.exe` (PyInstaller)

---

## Tech Stack

- **Backend:** FastAPI (Python)
- **UI:** HTML templates + HTMX-style interactions
- **Auth:** Cookie/session-based login
- **Packaging:** PyInstaller (Windows)

---

## Getting Started

### Requirements
- Python **3.10+**
### Install
```
git clone https://github.com/mohammad-saeed-code/SNMP-Magic.git
cd SNMP-Magic
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
