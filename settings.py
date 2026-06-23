"""Runtime, user-editable settings.

Stored as a single JSON blob in the database so the dashboard can change the
subnet, ports, scan cadence, categories and visibility without restarts. Values
fall back to the seed defaults in :mod:`config` on a fresh install.
"""
from __future__ import annotations

import json
import re
import threading

import config
import db

_lock = threading.Lock()
_KEY = "app"

# A scan target token: IPv4, CIDR, dash-range, or a bare hostname. Crucially it
# must NOT start with "-", so a malicious value can't smuggle in nmap flags.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-/]*$")
_PORTS_RE = re.compile(r"^[0-9,\-]+$")

# Keys we accept from clients, with their type validators applied in update().
_ALLOWED = {
    "targets", "full_targets", "ports", "interval", "service_detection",
    "timing", "skip_discovery", "docker_probe", "view", "host_sort",
    "categories", "hidden",
}


def defaults() -> dict:
    return {
        "targets": config.SUBNET,
        # Always scanned with -Pn + all ports, then merged in. For boxes a fast
        # sweep under-reports (notably the host running LAN Scout itself).
        "full_targets": config.FULL_TARGETS,
        "ports": config.PORTS,
        "interval": config.SCAN_INTERVAL,
        "service_detection": config.SERVICE_DETECTION,
        "timing": config.TIMING,
        # Skip nmap host discovery (-Pn): scan every target's ports even if it
        # doesn't answer ping. Essential when scanning specific IPs you know are
        # up, or hosts/subnets that block ping.
        "skip_discovery": config.SKIP_DISCOVERY,
        # Query the Docker API on hosts exposing 2375 to list their containers.
        "docker_probe": config.DOCKER_PROBE,
        "view": "host",          # "host" | "category"
        "host_sort": "ip",       # ip | label | services | last_seen
        "categories": [dict(c) for c in config.DEFAULT_CATEGORIES],
        "hidden": [],            # ["<ip>:<port>", …] individually hidden services
    }


def get() -> dict:
    data = defaults()
    raw = db.get_setting(_KEY)
    if raw:
        try:
            stored = json.loads(raw)
            if isinstance(stored, dict):
                data.update({k: stored[k] for k in stored if k in _ALLOWED})
        except (json.JSONDecodeError, TypeError):
            pass
    return data


def update(patch: dict) -> dict:
    """Validate and merge a partial settings update; return the full settings."""
    with _lock:
        cur = get()
        for k, v in patch.items():
            if k not in _ALLOWED:
                continue
            cur[k] = _validate(k, v, cur[k])
        db.set_setting(_KEY, json.dumps(cur))
        return cur


def _validate(key: str, value, previous):
    if key == "targets":
        tokens = [t for t in re.split(r"[\s,]+", str(value).strip()) if t]
        valid = [t for t in tokens if _TARGET_RE.match(t)]
        return " ".join(valid) if valid else previous
    if key == "full_targets":
        # Same validation as targets, but an empty value is allowed (= disabled).
        tokens = [t for t in re.split(r"[\s,]+", str(value).strip()) if t]
        return " ".join(t for t in tokens if _TARGET_RE.match(t))
    if key == "ports":
        s = str(value).strip()
        if s == "-" or _PORTS_RE.match(s):
            return s
        return previous
    if key == "interval":
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return previous
    if key == "timing":
        s = str(value)
        return s if s in {"0", "1", "2", "3", "4", "5"} else previous
    if key in ("service_detection", "skip_discovery", "docker_probe"):
        return bool(value)
    if key == "view":
        return value if value in {"host", "category"} else previous
    if key == "host_sort":
        return value if value in {"ip", "label", "services", "last_seen"} \
            else previous
    if key == "categories":
        return _sanitize_categories(value, previous)
    if key == "hidden":
        if isinstance(value, list):
            return [str(x) for x in value][:5000]
        return previous
    return previous


def _sanitize_categories(value, previous):
    if not isinstance(value, list):
        return previous
    out = []
    for i, c in enumerate(value):
        if not isinstance(c, dict) or not c.get("name"):
            continue
        out.append({
            "id": str(c.get("id") or f"cat{i}"),
            "name": str(c["name"])[:60],
            "color": str(c.get("color") or "#888")[:9],
            "order": int(c.get("order", i + 1)) if str(c.get("order", "")).lstrip("-").isdigit() else i + 1,
            "visible": bool(c.get("visible", True)),
            "ports": [int(p) for p in c.get("ports", [])
                      if str(p).isdigit() and 0 < int(p) < 65536],
            "services": [str(s).lower() for s in c.get("services", []) if s],
        })
    return out
