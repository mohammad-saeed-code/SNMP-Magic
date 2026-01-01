import os
import sys
import socket
import threading
import time
import webbrowser
import ctypes
from contextlib import closing

import uvicorn
import server  # server.app


APP_HOST = "127.0.0.1"
DEFAULT_PORT = 8080


def show_error(title: str, message: str):
    # MB_ICONERROR = 0x10, MB_OK = 0x0
    ctypes.windll.user32.MessageBoxW(None, message, title, 0x10 | 0x0)


def ensure_std_streams():
    # In windowed/frozen apps (PyInstaller --noconsole), these can be None.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")


def wait_for_listen(host: str, port: int, timeout_s: float = 10.0) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def find_free_port(preferred: int) -> int:
    def is_free(p: int) -> bool:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.connect_ex((APP_HOST, p)) != 0

    if is_free(preferred):
        return preferred

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind((APP_HOST, 0))
        return int(s.getsockname()[1])


class UvicornRunner:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self):
        ensure_std_streams()

        config = uvicorn.Config(
            server.app,
            host=self.host,
            port=self.port,
            log_level="info",
            reload=False,
            access_log=False,
        )
        self._server = uvicorn.Server(config)

        def run():
            self._server.run()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            self._server.should_exit = True
        time.sleep(0.4)


def main():
    port = find_free_port(DEFAULT_PORT)
    runner = UvicornRunner(APP_HOST, port)
    runner.start()

    if not wait_for_listen(APP_HOST, port, timeout_s=10.0):
        show_error(
            "SNMP-Magic failed to start",
            f"SNMP-Magic could not start its local server.\n\n"
            f"Port attempted: {port}\n\n"
            f"Possible causes:\n"
            f"- Another service is using the port\n"
            f"- Firewall or security software blocked it\n"
            f"- Internal startup error\n\n"
            f"Check logs and try again."
        )
        return

    url = f"http://{APP_HOST}:{port}/login"
    webbrowser.open(url)

    # Keep the process alive (so the server keeps running)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()


if __name__ == "__main__":
    main()
