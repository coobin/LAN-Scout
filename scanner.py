"""nmap-driven discovery: run a scan, parse the XML, return structured hosts.

Runs an unprivileged TCP connect scan (``-sT``) so no sudo is required. Service
detection (``-sV``) is optional and controlled via config.
"""
from __future__ import annotations

import os
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


def build_command(targets: str, ports: str, service_detection: bool,
                  timing: str, skip_discovery: bool = False) -> list[str]:
    # Run as root → let nmap use ARP host discovery + a SYN scan, which is the
    # accurate way to enumerate devices on a local segment. Unprivileged → fall
    # back to a TCP connect scan (no sudo needed, but misses ping-silent hosts).
    privileged = hasattr(os, "geteuid") and os.geteuid() == 0
    cmd = ["nmap", "--open", f"-T{timing}"]
    cmd.append("-sS" if privileged else "-sT")
    if skip_discovery:
        # -Pn: don't ping first; scan every target's ports regardless. Essential
        # for specific IPs / ping-blocked or cross-subnet hosts.
        cmd.append("-Pn")
    if service_detection:
        # Full-intensity -sV: probes harder to identify the actual product and
        # version (nginx 1.25, OpenSSH 9.6, MySQL 8.0 …), not just the port's
        # default service name. Slower than --version-light but far more useful.
        cmd += ["-sV"]
    if ports and ports != "-":
        cmd += ["-p", ports]
    # Targets are validated upstream (settings._TARGET_RE) and passed as
    # separate argv tokens, so no shell and no flag injection.
    cmd += ["-oX", "-"]
    cmd += [t for t in targets.split() if t]
    return cmd


def scan(targets: str, ports: str = config.PORTS,
         service_detection: bool = config.SERVICE_DETECTION,
         timing: str = config.TIMING,
         skip_discovery: bool = config.SKIP_DISCOVERY) -> list[dict]:
    """Run nmap and return a list of host dicts. Raises on failure.

    Caller is responsible for persisting the result. The scan is serialized:
    concurrent callers raise RuntimeError rather than piling up nmap processes.
    """
    if not nmap_available():
        raise RuntimeError("nmap is not installed or not on PATH")
    if not _scan_lock.acquire(blocking=False):
        raise RuntimeError("a scan is already in progress")
    _scanning.set()
    try:
        proc = subprocess.run(
            build_command(targets, ports, service_detection, timing,
                          skip_discovery),
            capture_output=True, text=True, timeout=3600,
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
            g = (lambda k: svc.get(k) if svc is not None else None)
            # extrainfo often carries useful detail like "Ubuntu", "protocol 2.0"
            # or "PHP 8.2"; fold it into version so the UI shows one tidy string.
            extra = g("extrainfo")
            version = g("version")
            if extra:
                version = f"{version} ({extra})" if version else extra
            services.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "name": g("name"),
                "product": g("product"),
                "version": version,
            })

        # nmap can report a host as up with no open ports when service
        # detection is off; keep it so the user still sees the device.
        hosts.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "hostname": hostname, "services": services,
        })
    return hosts
