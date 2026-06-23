"""LAN Scout HTTP server.

Zero third-party dependencies: stdlib http.server for the API + static files,
a background thread for periodic scans, and SQLite for persistence.

Run:  python3 server.py
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
import db
import scanner

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def run_scan(subnet: str | None = None) -> None:
    """Execute one scan and persist it. Swallows errors into the scans table."""
    subnet = subnet or config.SUBNET
    scan_id = db.start_scan(subnet)
    try:
        hosts = scanner.scan(subnet)
        db.save_results(hosts)
        db.finish_scan(scan_id, len(hosts))
        print(f"[scan] {subnet}: {len(hosts)} host(s) up")
    except Exception as e:  # noqa: BLE001 - record any failure for the UI
        db.finish_scan(scan_id, 0, str(e))
        print(f"[scan] error: {e}")


def trigger_scan_async(subnet: str | None = None) -> bool:
    """Kick off a scan in a worker thread if one isn't already running."""
    if scanner.is_scanning():
        return False
    threading.Thread(target=run_scan, args=(subnet,), daemon=True).start()
    return True


def scheduler_loop() -> None:
    if config.SCAN_INTERVAL <= 0:
        return
    while True:
        time.sleep(config.SCAN_INTERVAL)
        if not scanner.is_scanning():
            run_scan()


class Handler(BaseHTTPRequestHandler):
    server_version = "LANScout/1.0"

    # -- helpers ---------------------------------------------------------
    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _serve_static(self, path: str) -> None:
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            self.send_error(404, "Not found")
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(os.path.splitext(full)[1], "application/octet-stream")
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # -- routes ----------------------------------------------------------
    def do_GET(self) -> None:
        try:
            if self.path == "/api/state":
                return self._state()
            if self.path.startswith("/api/"):
                return self._json({"error": "unknown endpoint"}, 404)
            return self._serve_static(self.path.split("?")[0])
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.send_error(500, "Internal error")

    def do_POST(self) -> None:
        try:
            if self.path == "/api/scan":
                started = trigger_scan_async()
                return self._json({"started": started,
                                   "scanning": scanner.is_scanning()})
            if self.path.startswith("/api/host/"):
                ip = self.path[len("/api/host/"):]
                body = self._read_json()
                ok = db.update_host_meta(
                    ip, (body.get("label") or "").strip() or None,
                    (body.get("note") or "").strip() or None)
                return self._json({"ok": ok}, 200 if ok else 404)
            return self._json({"error": "unknown endpoint"}, 404)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.send_error(500, "Internal error")

    def _state(self) -> None:
        self._json({
            "config": {
                "subnet": config.SUBNET,
                "interval": config.SCAN_INTERVAL,
                "service_detection": config.SERVICE_DETECTION,
            },
            "scanning": scanner.is_scanning(),
            "nmap_available": scanner.nmap_available(),
            "last_scan": db.last_scan(),
            "hosts": db.get_hosts(),
        })

    def log_message(self, fmt, *args):  # quieter logs
        return


def main() -> None:
    db.init()
    if not scanner.nmap_available():
        print("WARNING: nmap not found on PATH — scans will fail until installed.")

    threading.Thread(target=scheduler_loop, daemon=True).start()
    # Kick off an initial scan so the page isn't empty on first load.
    trigger_scan_async()

    httpd = ThreadingHTTPServer((config.HOST, config.PORT), Handler)
    url = f"http://{config.HOST}:{config.PORT}"
    print(f"LAN Scout running at {url}")
    print(f"  subnet={config.SUBNET}  interval={config.SCAN_INTERVAL}s  "
          f"sV={'on' if config.SERVICE_DETECTION else 'off'}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
