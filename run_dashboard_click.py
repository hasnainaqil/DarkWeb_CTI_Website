from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


def _notify(title: str, message: str) -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(title, message)
        root.destroy()
    except Exception:
        print(f"{title}: {message}")


def _ask_password_gui() -> str | None:
    try:
        import tkinter as tk

        password: str | None = None

        root = tk.Tk()
        root.title("Supabase DB password")
        root.geometry("420x140")
        root.resizable(False, False)

        tk.Label(root, text="Enter Supabase DB password:").pack(pady=(12, 6))

        entry = tk.Entry(root, show="*", width=48)
        entry.pack(pady=(0, 10))
        entry.focus_set()

        def ok() -> None:
            nonlocal password
            password = entry.get()
            root.destroy()

        def cancel() -> None:
            root.destroy()

        btn_row = tk.Frame(root)
        btn_row.pack(pady=(0, 10))
        tk.Button(btn_row, text="OK", width=10, command=ok).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_row, text="Cancel", width=10, command=cancel).pack(side=tk.LEFT, padx=8)

        root.mainloop()
        return password
    except Exception:
        return None


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return int(s.getsockname()[1])


def _wait_for_listen(host: str, port: int, timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> int:
    project_dir = Path(__file__).resolve().parent
    workspace_dir = project_dir.parent

    venv_python = workspace_dir / ".venv" / "Scripts" / "python.exe"
    python_exe = str(venv_python if venv_python.exists() else Path(sys.executable))

    password = os.getenv("SUPABASE_DB_PASSWORD") or os.getenv("PGPASSWORD")
    if not password:
        password = _ask_password_gui()
        if not password:
            try:
                import getpass

                password = getpass.getpass("Supabase DB password: ")
            except Exception:
                password = None
        if not password:
            msg = (
                "Missing DB password.\n\n"
                "Option A (recommended): set env var SUPABASE_DB_PASSWORD, then click Run again.\n"
                "PowerShell (one-time):\n"
                "  setx SUPABASE_DB_PASSWORD \"<YOUR_PASSWORD>\"\n\n"
                "Option B: click Run again and enter the password in the prompt (if supported)."
            )
            _notify("DarkWeb CTI Dashboard", msg)
            return 1

    env = os.environ.copy()

    # Supabase Session Pooler defaults (IPv4 compatible)
    env.setdefault("PGHOST", "aws-1-ap-northeast-2.pooler.supabase.com")
    env.setdefault("PGPORT", "5432")
    env.setdefault("PGDATABASE", "postgres")
    env.setdefault("PGUSER", "postgres.ypefuoljwvczzmivbgmb")
    env.setdefault("PGSSLMODE", "require")

    # The dashboard reads this table by default
    env.setdefault("DWCTI_TABLE", 'public."DarkWeb_CTI_Data"')

    # Set password for this process only
    env["PGPASSWORD"] = password

    port = _pick_free_port()
    url = f"http://127.0.0.1:{port}"

    args = [
        python_exe,
        "-m",
        "streamlit",
        "run",
        str(project_dir / "dashboard_app.py"),
        "--server.headless",
        "true",
        "--server.port",
        str(port),
    ]

    print(f"Starting Streamlit using: {python_exe}")

    # Start Streamlit detached so click-run returns quickly, but the web app stays running.
    creationflags = 0
    if sys.platform.startswith("win"):
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    proc = subprocess.Popen(args, cwd=str(project_dir), env=env, creationflags=creationflags)

    # Wait for Streamlit to listen on the chosen port, then open exactly that URL.
    if _wait_for_listen("127.0.0.1", port, timeout_s=12.0):
        webbrowser.open(url)
    else:
        _notify(
            "DarkWeb CTI Dashboard",
            "Streamlit is taking longer than expected to start. Check the VS Code Terminal output.",
        )

    # If Streamlit fails immediately, surface that.
    time.sleep(0.6)
    if proc.poll() not in (None, 0):
        _notify("DarkWeb CTI Dashboard", "Streamlit failed to start. Check the VS Code Terminal output for errors.")
        return int(proc.returncode or 1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
