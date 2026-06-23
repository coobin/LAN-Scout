"""Docker discovery: enumerate containers via the Docker Engine API.

Port scanning is hopeless for a docker host — most containers either don't
publish to the host or sit behind a reverse proxy on a bridge network. Asking
the Docker API instead gives the authoritative, complete list of what's running.

We query the plain-HTTP API (TCP 2375). TLS (2376) needs client certs and is
skipped. Only used against hosts where the scan already found 2375/2376 open.
"""
from __future__ import annotations

import json
import urllib.request

# Docker daemon TCP ports we know how to talk to (2376 is TLS — best-effort).
DOCKER_PORTS = (2375, 2376)


def containers_for(host: str, open_ports: set[int], timeout: float = 4.0) -> list[dict]:
    """Return running containers on ``host`` if it exposes the Docker API.

    ``open_ports`` is the set of ports the scan found open on the host; we only
    bother if a Docker port is among them. Any failure yields an empty list —
    discovery must never break a scan.
    """
    for port in DOCKER_PORTS:
        if port not in open_ports:
            continue
        scheme = "https" if port == 2376 else "http"
        try:
            return _query(f"{scheme}://{host}:{port}", timeout)
        except Exception:  # noqa: BLE001 - unreachable / TLS / not docker, skip
            continue
    return []


def _query(base: str, timeout: float) -> list[dict]:
    with urllib.request.urlopen(f"{base}/containers/json", timeout=timeout) as r:
        data = json.load(r)
    out = []
    for c in data:
        name = (c.get("Names") or ["/?"])[0].lstrip("/")
        ports, seen = [], set()
        for p in c.get("Ports", []):
            key = (p.get("PublicPort"), p.get("PrivatePort"), p.get("Type"))
            if key in seen:
                continue
            seen.add(key)
            ports.append({
                "public": p.get("PublicPort"),
                "private": p.get("PrivatePort"),
                "type": p.get("Type"),
            })
        # Stable order: published ports first, then by private port.
        ports.sort(key=lambda x: (x["public"] is None, x["public"] or 0,
                                  x["private"] or 0))
        out.append({
            "name": name,
            "image": c.get("Image"),
            "state": c.get("State"),
            "status": c.get("Status"),
            "ports": ports,
        })
    out.sort(key=lambda c: c["name"])
    return out
