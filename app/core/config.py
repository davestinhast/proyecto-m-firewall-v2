import copy
import json
import platform
from pathlib import Path

from app.core.constants import CONFIG_FILE, SITES


DEFAULT_CONFIG = {
    "interfaces": {"wan": "eth0", "lan": "eth0"},
    "server_ip": "",
    "sites": {key: {"enabled": False} for key in SITES},
    "client_server": {
        "enabled": False,
        "client_ip": "",
        "server_ip": "",
        "protocols": ["tcp", "udp", "icmp"],
    },
    "mac_rules": [
        {"name": "Cliente", "mac": "", "enabled": False},
    ],
    "connection_limits": [
        {"name": "HTTP", "proto": "tcp", "port": 80, "max": 10, "enabled": False},
        {"name": "HTTPS", "proto": "tcp", "port": 443, "max": 10, "enabled": False},
        {"name": "SSH", "proto": "tcp", "port": 22, "max": 3, "enabled": False},
    ],
    "default_action": "DROP",
}


def config_path() -> Path:
    if platform.system() == "Linux":
        return Path(CONFIG_FILE)
    return Path(__file__).resolve().parents[2] / "config" / "firewall.json"


def load_config() -> dict:
    path = config_path()
    if not path.exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return copy.deepcopy(DEFAULT_CONFIG)
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    _merge(cfg, data)
    return cfg


def save_config(cfg: dict) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _merge(base: dict, override: dict) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
