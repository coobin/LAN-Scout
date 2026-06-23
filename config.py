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

# Skip host discovery (-Pn): treat every target as up and scan its ports.
# Needed for scanning specific IPs / ping-blocked hosts across subnets.
SKIP_DISCOVERY = os.environ.get("LANSCOUT_PN", "0") != "0"

# HTTP server bind.
HOST = os.environ.get("LANSCOUT_HOST", "127.0.0.1")
PORT = int(os.environ.get("LANSCOUT_PORT", "8770"))

# SQLite database path.
DB_PATH = os.environ.get(
    "LANSCOUT_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "lanscout.db"),
)

# The values above are *seed defaults*. Once the app runs, user-editable
# settings (subnet, ports, interval, categories, …) live in the database and
# override these — see settings.py. Environment variables only set the initial
# values on a fresh database.

# Default service categories used to group/sort/colour discovered services.
# A service joins the first category that lists its port OR its nmap name.
# Fully user-editable at runtime via the settings panel.
DEFAULT_CATEGORIES = [
    {"id": "web", "name": "Web / 控制台", "color": "#4f8cff", "order": 1,
     "visible": True,
     "ports": [80, 81, 443, 3000, 5000, 5001, 5601, 7860, 8000, 8006, 8008,
               8080, 8081, 8086, 8088, 8096, 8123, 8443, 8888, 9000, 9001,
               9090, 9443, 3128, 32400, 8500, 15672, 10000],
     "services": ["http", "https", "http-proxy", "http-alt", "https-alt",
                  "ssl/http"]},
    {"id": "remote", "name": "远程访问", "color": "#a78bfa", "order": 2,
     "visible": True,
     "ports": [22, 23, 3389, 5900],
     "services": ["ssh", "telnet", "ms-wbt-server", "rdp", "vnc"]},
    {"id": "db", "name": "数据库 / 缓存", "color": "#f59e0b", "order": 3,
     "visible": True,
     "ports": [1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017],
     "services": ["mysql", "postgresql", "redis", "mongodb", "ms-sql-s",
                  "oracle", "elasticsearch", "memcached", "couchdb"]},
    {"id": "file", "name": "文件 / 共享", "color": "#34d399", "order": 4,
     "visible": True,
     "ports": [21, 139, 445, 873, 2049, 990],
     "services": ["ftp", "ftps", "smb", "microsoft-ds", "netbios-ssn", "nfs",
                  "rsync"]},
    {"id": "infra", "name": "基础设施", "color": "#22d3ee", "order": 5,
     "visible": True,
     "ports": [53, 123, 161, 514, 5353, 6443, 2375, 2376, 8200],
     "services": ["domain", "dns", "snmp", "syslog", "ntp", "docker",
                  "kubernetes"]},
    {"id": "media", "name": "媒体 / 物联网", "color": "#fb7185", "order": 6,
     "visible": True,
     "ports": [554, 1883, 5060, 7070, 8009, 32400],
     "services": ["rtsp", "mqtt", "sip", "plex", "airplay"]},
]
