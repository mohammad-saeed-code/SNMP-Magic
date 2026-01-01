# snmp_magic/ui_env.py
from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.templating import Jinja2Templates

def app_base_dir() -> Path:
    # PyInstaller onefile
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]

    # PyInstaller onedir: assets live in "<exe_dir>/_internal"
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        internal = exe_dir / "_internal"
        if internal.is_dir():
            return internal
        return exe_dir

    # Normal python run (project root)
    return Path(__file__).resolve().parent.parent


BASE_DIR = app_base_dir()

templates_dir_env = os.getenv("TEMPLATES_DIR")
templates_dir = Path(templates_dir_env) if templates_dir_env else (BASE_DIR / "templates")
templates_dir = templates_dir.resolve()

templates = Jinja2Templates(directory=str(templates_dir))
