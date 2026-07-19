import platform
import re
import socket
import subprocess


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_root() -> bool:
    if not is_linux():
        return False
    try:
        import os
        return os.geteuid() == 0
    except Exception:
        return False


def own_ip_and_iface() -> tuple[str, str]:
    if not is_linux():
        return "127.0.0.1", "eth0"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
    except Exception:
        ip = "127.0.0.1"
    try:
        result = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True, timeout=5)
        match = re.search(r"dev\s+(\S+)", result.stdout)
        iface = match.group(1) if match else "eth0"
    except Exception:
        iface = "eth0"
    return ip, iface


def run(cmd: list[str], input_text: str | None = None) -> tuple[int, str, str]:
    try:
        result = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=60)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"
