"""nmap-driven discovery: run a scan, parse the XML, return structured hosts.

Runs an unprivileged TCP connect scan (``-sT``) so no sudo is required. Service
detection (``-sV``) is optional and controlled via config.
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET

import config

# Guards against two scans running at once (auto-scan + a manual trigger).
_scan_lock = threading.Lock()
_scanning = threading.Event()


def is_scanning() -> bool:
    return _scanning.is_set()


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def build_command(subnet: str) -> list[str]:
    cmd = ["nmap", "-sT", "--open", f"-T{config.TIMING}"]
    if config.SERVICE_DETECTION:
        cmd += ["-sV", "--version-light"]
    if config.PORTS and config.PORTS != "-":
        cmd += ["-p", config.PORTS]
    cmd += ["-oX", "-", subnet]
    return cmd


def scan(subnet: str | None = None) -> list[dict]:
    """Run nmap and return a list of host dicts. Raises on failure.

    Caller is responsible for persisting the result. The scan is serialized:
    concurrent callers raise RuntimeError rather than piling up nmap processes.
    """
    subnet = subnet or config.SUBNET
    if not nmap_available():
        raise RuntimeError("nmap is not installed or not on PATH")
    if not _scan_lock.acquire(blocking=False):
        raise RuntimeError("a scan is already in progress")
    _scanning.set()
    try:
        proc = subprocess.run(
            build_command(subnet),
            capture_output=True, text=True, timeout=1800,
        )
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(
                f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()}"
            )
        return parse_xml(proc.stdout)
    finally:
        _scanning.clear()
        _scan_lock.release()


def parse_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = mac = vendor = hostname = None
        for addr in host_el.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4":
                ip = addr.get("addr")
            elif kind == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        if not ip:
            continue

        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        services = []
        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_el.find("service")
            services.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "name": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })

        # nmap can report a host as up with no open ports when service
        # detection is off; keep it so the user still sees the device.
        hosts.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "hostname": hostname, "services": services,
        })
    return hosts
