"""SQLite persistence for LAN Scout.

Two kinds of data live here:

* discovered state (hosts + their open services), refreshed every scan;
* user-owned metadata (label, note) that survives across scans.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager

import config

_lock = threading.Lock()


@contextmanager
def _conn():
    # One connection per call keeps things simple and thread-safe enough for a
    # single-user dashboard; the module-level lock serializes writers.
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init() -> None:
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                ip          TEXT PRIMARY KEY,
                mac         TEXT,
                vendor      TEXT,
                hostname    TEXT,
                label       TEXT,
                note        TEXT,
                is_up       INTEGER NOT NULL DEFAULT 1,
                first_seen  REAL NOT NULL,
                last_seen   REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS services (
                ip          TEXT NOT NULL,
                port        INTEGER NOT NULL,
                protocol    TEXT NOT NULL DEFAULT 'tcp',
                name        TEXT,
                product     TEXT,
                version     TEXT,
                last_seen   REAL NOT NULL,
                PRIMARY KEY (ip, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  REAL NOT NULL,
                finished_at REAL,
                subnet      TEXT,
                host_count  INTEGER,
                error       TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS containers (
                ip        TEXT NOT NULL,
                name      TEXT NOT NULL,
                image     TEXT,
                state     TEXT,
                status    TEXT,
                ports     TEXT,              -- JSON: [{public,private,type}]
                last_seen REAL NOT NULL,
                PRIMARY KEY (ip, name)
            );
            """
        )


def get_setting(key: str) -> str | None:
    with _conn() as c:
        row = c.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None


def set_setting(key: str, value: str) -> None:
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )


def start_scan(subnet: str) -> int:
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (started_at, subnet) VALUES (?, ?)",
            (time.time(), subnet),
        )
        return cur.lastrowid


def finish_scan(scan_id: int, host_count: int, error: str | None = None) -> None:
    with _lock, _conn() as c:
        c.execute(
            "UPDATE scans SET finished_at=?, host_count=?, error=? WHERE id=?",
            (time.time(), host_count, error, scan_id),
        )


def save_results(hosts: list[dict]) -> None:
    """Upsert discovered hosts and replace their service rows.

    ``label`` and ``note`` are never overwritten here — they belong to the user.
    """
    now = time.time()
    seen_ips = [h["ip"] for h in hosts]
    with _lock, _conn() as c:
        # Mark every previously-known host as down; scanned ones flip back up.
        c.execute("UPDATE hosts SET is_up=0")
        for h in hosts:
            c.execute(
                """
                INSERT INTO hosts (ip, mac, vendor, hostname, is_up,
                                   first_seen, last_seen)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=COALESCE(excluded.mac, hosts.mac),
                    vendor=COALESCE(excluded.vendor, hosts.vendor),
                    hostname=COALESCE(excluded.hostname, hosts.hostname),
                    is_up=1,
                    last_seen=excluded.last_seen
                """,
                (h["ip"], h.get("mac"), h.get("vendor"), h.get("hostname"),
                 now, now),
            )
        # Refresh services only for hosts we just scanned.
        if seen_ips:
            placeholders = ",".join("?" * len(seen_ips))
            c.execute(
                f"DELETE FROM services WHERE ip IN ({placeholders})", seen_ips
            )
        for h in hosts:
            for s in h.get("services", []):
                c.execute(
                    """
                    INSERT OR REPLACE INTO services
                        (ip, port, protocol, name, product, version, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (h["ip"], s["port"], s.get("protocol", "tcp"),
                     s.get("name"), s.get("product"), s.get("version"), now),
                )
        # Refresh docker containers for scanned hosts (only those probed carry
        # a "containers" key; a host without the key keeps its old rows).
        probed = [h["ip"] for h in hosts if "containers" in h]
        if probed:
            placeholders = ",".join("?" * len(probed))
            c.execute(
                f"DELETE FROM containers WHERE ip IN ({placeholders})", probed
            )
        for h in hosts:
            for ct in h.get("containers", []):
                c.execute(
                    """
                    INSERT OR REPLACE INTO containers
                        (ip, name, image, state, status, ports, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (h["ip"], ct["name"], ct.get("image"), ct.get("state"),
                     ct.get("status"), json.dumps(ct.get("ports", [])), now),
                )


def update_host_meta(ip: str, label: str | None, note: str | None) -> bool:
    with _lock, _conn() as c:
        cur = c.execute(
            "UPDATE hosts SET label=?, note=? WHERE ip=?", (label, note, ip)
        )
        return cur.rowcount > 0


def get_hosts() -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM hosts").fetchall()
        hosts = [dict(r) for r in rows]
        svc = c.execute("SELECT * FROM services ORDER BY port").fetchall()
        cts = c.execute("SELECT * FROM containers ORDER BY name").fetchall()
    by_ip: dict[str, list] = {}
    for s in svc:
        by_ip.setdefault(s["ip"], []).append(dict(s))
    ct_by_ip: dict[str, list] = {}
    for ct in cts:
        d = dict(ct)
        try:
            d["ports"] = json.loads(d["ports"]) if d.get("ports") else []
        except (json.JSONDecodeError, TypeError):
            d["ports"] = []
        ct_by_ip.setdefault(ct["ip"], []).append(d)
    for h in hosts:
        h["services"] = by_ip.get(h["ip"], [])
        h["containers"] = ct_by_ip.get(h["ip"], [])
    # Sort hosts by numeric IP for a tidy list.
    hosts.sort(key=lambda h: (0 if h["is_up"] else 1, _ip_key(h["ip"])))
    return hosts


def last_scan() -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


def _ip_key(ip: str) -> tuple:
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999,)
