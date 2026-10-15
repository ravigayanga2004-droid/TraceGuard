"""Exercise installed CLI and a real loopback HTTP server using temporary data."""

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn

from traceguard.api.app import create_app


def main() -> None:
    with TemporaryDirectory(prefix="traceguard-validation-") as temporary:
        base = Path(temporary)
        root, state = base / "files", base / "state"
        root.mkdir()

        def cli(*arguments: str) -> None:
            result = subprocess.run(
                [sys.executable, "-m", "traceguard", *arguments, "--state", str(state)],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            print(result.stdout.strip())

        cli("init", str(root))
        path = root / "test.txt"
        path.write_text("first", encoding="utf-8")
        cli("scan")
        path.write_text("second", encoding="utf-8")
        cli("scan")
        path.rename(root / "renamed.txt")
        cli("scan")
        (root / "renamed.txt").unlink()
        cli("scan")
        for format in ("json", "markdown", "html"):
            cli("report", "--format", format, "--output", str(base / f"report.{format}"))
        data = json.loads((base / "report.json").read_text(encoding="utf-8"))
        assert {e["kind"] for e in data["events"]} == {"created", "modified", "renamed", "deleted"}
        cli("integrity")
        cli("status")
        # A real listening socket; Uvicorn is stopped via its public should_exit flag.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            server = uvicorn.Server(
                uvicorn.Config(create_app(state), host="127.0.0.1", port=port, log_level="warning")
            )
            worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]})
            worker.start()
            try:
                deadline = time.monotonic() + 10
                while not server.started and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert server.started, "Dashboard did not start"
                # Ignore proxy environment variables for the strictly local check.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f"http://127.0.0.1:{port}/", timeout=5) as response:
                    assert response.status == 200
                    assert b"TraceGuard" in response.read()
                with opener.open(f"http://127.0.0.1:{port}/api/status", timeout=5) as response:
                    assert json.load(response)["event_count"] == 4
                print(f"Dashboard verified at http://127.0.0.1:{port}")
            finally:
                server.should_exit = True
                worker.join(timeout=10)
                assert not worker.is_alive(), "Dashboard did not stop"
        print("CLI lifecycle, reports, loopback dashboard, and clean shutdown passed.")


if __name__ == "__main__":
    main()
