"""Own ephemeral loopback app processes, sockets and private configuration."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import httpx


HERE = Path(__file__).resolve().parent


@contextmanager
def application(name, config):
    if name not in ("backend", "caller", "portal", "security"):
        raise ValueError("Unknown application fixture")
    with tempfile.TemporaryDirectory(prefix="connected-app-") as directory:
        path = Path(directory).resolve() / "config.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(config, handle)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
            env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG") if key in os.environ}
            env.update({"PYTHONNOUSERSITE": "1", "AZURE_TENANT_ID": "fixture-tenant",
                        "AGENT_NAME": "budget-report"})
            process = subprocess.Popen(
                [sys.executable, str(HERE / "apps.py"), "--app", name,
                 "--socket-fd", str(listener.fileno()), "--config", str(path)],
                env=env, pass_fds=(listener.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        try:
            ready = False
            endpoint = "/api/auth-config" if name == "portal" else "/health"
            with httpx.Client(trust_env=False, timeout=0.5, follow_redirects=False) as client:
                deadline = time.monotonic() + 20
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        response = client.get(origin + endpoint)
                        ready = response.status_code == 200
                    except httpx.RequestError:
                        ready = False
                    if ready:
                        break
                    time.sleep(0.05)
            if not ready:
                raise RuntimeError("Local application did not become ready")
            yield origin
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
