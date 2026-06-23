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


from concurrent.futures import ThreadPoolExecutor


def _fetch_stats(base: str, c_id: str, timeout: float) -> dict | None:
    try:
        with urllib.request.urlopen(f"{base}/containers/{c_id}/stats?stream=false", timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def _query(base: str, timeout: float) -> list[dict]:
    with urllib.request.urlopen(f"{base}/containers/json", timeout=timeout) as r:
        data = json.load(r)
    
    # Concurrently fetch stats for running containers
    running = [c for c in data if c.get("State") == "running"]
    stats_map = {}
    if running:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_fetch_stats, base, c["Id"], min(timeout, 2.0)): c["Id"]
                for c in running
            }
            for f in futures:
                c_id = futures[f]
                res = f.result()
                if res:
                    stats_map[c_id] = res

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
        ports.sort(key=lambda x: (x["public"] is None, x["public"] or 0,
                                  x["private"] or 0))
        
        cpu_str = ""
        mem_str = ""
        stats = stats_map.get(c.get("Id"))
        if stats:
            try:
                cpu_stats = stats.get("cpu_stats", {})
                precpu_stats = stats.get("precpu_stats", {})
                cpu_usage = cpu_stats.get("cpu_usage", {})
                precpu_usage = precpu_stats.get("cpu_usage", {})
                
                cpu_delta = cpu_usage.get("total_usage", 0) - precpu_usage.get("total_usage", 0)
                system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)
                
                if system_delta > 0 and cpu_delta > 0:
                    online_cpus = cpu_stats.get("online_cpus") or len(cpu_usage.get("percpu_usage") or [1])
                    cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
                else:
                    cpu_percent = 0.0
                cpu_str = f"{cpu_percent:.1f}%"
            except Exception:
                cpu_str = ""
                
            try:
                mem_stats = stats.get("memory_stats", {})
                usage = mem_stats.get("usage", 0)
                limit = mem_stats.get("limit", 1)
                usage_mb = usage / (1024 * 1024)
                if limit > 0:
                    mem_percent = (usage / limit) * 100.0
                    mem_str = f"{usage_mb:.1f}MB ({mem_percent:.1f}%)"
                else:
                    mem_str = f"{usage_mb:.1f}MB"
            except Exception:
                mem_str = ""

        out.append({
            "name": name,
            "image": c.get("Image"),
            "state": c.get("State"),
            "status": c.get("Status"),
            "ports": ports,
            "cpu": cpu_str,
            "mem": mem_str,
        })
    out.sort(key=lambda c: c["name"])
    return out
