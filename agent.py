#!/usr/bin/env python3
"""
Cross-platform Asset Inventory Agent
Supports: Linux, macOS, Windows
"""

import platform
import socket
import uuid
import json
import time
import os
import sys
import psutil
import requests
from datetime import datetime

# =====================
# CONFIGURATION
# =====================

AGENT_VERSION = "0.1.0"
BACKEND_URL = "https://imxx.requestcatcher.com/"
REQUEST_TIMEOUT = 10  # seconds

# Optional: set via env var
AGENT_TOKEN = os.getenv("ASSET_AGENT_TOKEN", "")

# =====================
# UTILS
# =====================

def now_utc():
    return datetime.utcnow().isoformat() + "Z"

def safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default

# =====================
# HOST IDENTITY
# =====================

def host_identity():
    return {
        "hostname": socket.gethostname(),
        "fqdn": safe_call(socket.getfqdn),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "machine_id": hex(uuid.getnode()),
    }

# =====================
# HARDWARE
# =====================

def hardware_info():
    return {
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "memory_mb": round(psutil.virtual_memory().total / 1024 / 1024),
        "disk_total_gb": round(psutil.disk_usage("/").total / 1024 / 1024 / 1024, 2),
    }

# =====================
# NETWORK
# =====================

def network_info():
    interfaces = {}

    for name, addrs in psutil.net_if_addrs().items():
        interfaces[name] = []
        for addr in addrs:
            interfaces[name].append({
                "family": str(addr.family),
                "address": addr.address
            })

    return {
        "interfaces": interfaces,
        "connections_listening": safe_call(
            lambda: [
                {
                    "ip": c.laddr.ip,
                    "port": c.laddr.port,
                    "pid": c.pid
                }
                for c in psutil.net_connections(kind="inet")
                if c.status == psutil.CONN_LISTEN
            ],
            []
        )
    }

# =====================
# PROCESSES & SERVICES
# =====================

def running_processes(limit=50):
    processes = []
    for p in psutil.process_iter(attrs=["pid", "name", "username"]):
        if len(processes) >= limit:
            break
        info = p.info
        processes.append(info)
    return processes

# =====================
# USERS
# =====================

def local_users():
    return safe_call(
        lambda: [u.name for u in psutil.users()],
        []
    )

# =====================
# INSTALLED SOFTWARE (BEST-EFFORT)
# =====================

def installed_software():
    os_name = platform.system().lower()

    try:
        if os_name == "linux":
            return list_linux_packages()
        elif os_name == "darwin":
            return list_macos_packages()
        elif os_name == "windows":
            return list_windows_packages()
    except Exception:
        pass

    return []

def list_linux_packages():
    pkgs = []
    if os.path.exists("/usr/bin/dpkg"):
        stream = os.popen("dpkg -l")
        for line in stream.readlines():
            if line.startswith("ii"):
                parts = line.split()
                pkgs.append({"name": parts[1], "version": parts[2]})
    elif os.path.exists("/usr/bin/rpm"):
        stream = os.popen("rpm -qa")
        for line in stream.readlines():
            pkgs.append({"name": line.strip()})
    return pkgs

def list_macos_packages():
    pkgs = []
    if os.path.exists("/usr/local/bin/brew"):
        stream = os.popen("brew list --versions")
        for line in stream.readlines():
            parts = line.split()
            pkgs.append({"name": parts[0], "version": " ".join(parts[1:])})
    return pkgs

def list_windows_packages():
    # Lightweight, avoids Win32_Product slowness
    pkgs = []
    try:
        import winreg
        paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        for path in paths:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                try:
                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                    pkgs.append({"name": name, "version": version})
                except Exception:
                    pass
    except Exception:
        pass
    return pkgs

# =====================
# INVENTORY PAYLOAD
# =====================

def collect_inventory():
    return {
        "agent": {
            "version": AGENT_VERSION,
            "timestamp": now_utc()
        },
        "identity": host_identity(),
        "hardware": hardware_info(),
        "network": network_info(),
        "processes": running_processes(),
        "users": local_users(),
        "software": installed_software(),
    }

# =====================
# SEND TO BACKEND
# =====================

def send_inventory(payload):
    # 1. Save payload locally (overwrite if exists)
    try:
        with open("asset.json", "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to write asset.json: {e}")

    # 2. Prepare headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"asset-agent/{AGENT_VERSION}",
    }

    if AGENT_TOKEN:
        headers["Authorization"] = f"Bearer {AGENT_TOKEN}"

    # 3. Send to backend
    response = requests.post(
        BACKEND_URL,
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT
    )

    return response.status_code, response.text


# =====================
# MAIN
# =====================

def main():
    try:
        inventory = collect_inventory()
        status, resp = send_inventory(inventory)
        print(f"[+] Inventory sent successfully ({status})")
    except Exception as e:
        print(f"[!] Agent error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
