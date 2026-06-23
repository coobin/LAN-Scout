"""Runtime configuration for LAN Scout.

Values come from environment variables (prefix ``LANSCOUT_``) with sane
defaults. Nothing here requires external packages.
"""
from __future__ import annotations

import os
import socket
import subprocess


def _default_subnet() -> str:
    """Best-effort guess of the local /24 subnet, e.g. ``10.1.22.0/24``.

    We look at the IP of the interface that owns the route to the outside
    world, then assume a /24. Override with LANSCOUT_SUBNET if wrong.
    """
    ip = None
    # Trick: opening a UDP socket to a public IP reveals our primary local IP
    # without sending any packet.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        pass

    # On a VPN the trick above can return the tunnel IP. Prefer en0 on macOS.
    try:
        en0 = subprocess.run(
            ["ipconfig", "getifaddr", "en0"],
            capture_output=True, text=True, timeout=2,
        ).stdout.strip()
        if en0:
            ip = en0
    except (OSError, subprocess.SubprocessError):
        pass

    if not ip or ip.startswith("127."):
        return "192.168.1.0/24"
    octets = ip.split(".")
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


# Network range to scan, CIDR notation.
SUBNET = os.environ.get("LANSCOUT_SUBNET") or _default_subnet()

# Ports nmap probes. A curated list of common service ports keeps scans fast.
# Set LANSCOUT_PORTS to "-" to scan nmap's full default top-1000 set.
PORTS = os.environ.get(
    "LANSCOUT_PORTS",
    "21,22,23,25,53,80,81,88,110,143,389,443,445,465,514,515,587,631,"
    "873,902,990,993,995,1080,1433,1521,1883,2049,2375,2376,3000,3128,"
    "3306,3389,4444,5000,5001,5060,5432,5601,5672,5900,5984,6000,6379,"
    "6443,7001,7070,7860,8000,8006,8008,8009,8080,8081,8086,8088,8096,"
    "8123,8200,8443,8500,8888,9000,9001,9090,9100,9200,9443,9999,10000,"
    "11211,15672,27017,32400,49152,50000",
)

# Seconds between automatic background scans. 0 disables auto-scan.
SCAN_INTERVAL = int(os.environ.get("LANSCOUT_INTERVAL", "900"))

# nmap timing template (0-5). 4 is fast and LAN-friendly.
TIMING = os.environ.get("LANSCOUT_TIMING", "4")

# Run nmap service/version detection (-sV). Slower but identifies products.
SERVICE_DETECTION = os.environ.get("LANSCOUT_SV", "1") != "0"

# HTTP server bind.
HOST = os.environ.get("LANSCOUT_HOST", "127.0.0.1")
PORT = int(os.environ.get("LANSCOUT_PORT", "8770"))

# SQLite database path.
DB_PATH = os.environ.get(
    "LANSCOUT_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "lanscout.db"),
)
