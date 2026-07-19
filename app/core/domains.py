import socket

from app.core.constants import SITES, IPSET_PREFIX


FALLBACK_IPS = {
    "youtube": [
        "142.250.0.0/15",
        "142.251.0.0/16",
        "172.217.0.0/16",
        "172.253.0.0/16",
        "216.58.192.0/19",
        "216.239.32.0/19",
        "64.233.160.0/19",
        "74.125.0.0/16",
        "108.177.0.0/17",
    ],
    "facebook": ["157.240.0.0/16", "31.13.64.0/18", "57.144.0.0/16"],
    "hotmail": ["13.107.0.0/16", "40.96.0.0/13", "52.96.0.0/14", "204.79.197.0/24"],
}


def enabled_sites(cfg: dict) -> list[str]:
    sites_cfg = cfg.get("sites", {})
    return [key for key in SITES if sites_cfg.get(key, {}).get("enabled", False)]


def resolve_site(key: str) -> list[str]:
    values = set(FALLBACK_IPS.get(key, []))
    for domain in SITES[key]["domains"]:
        try:
            for item in socket.getaddrinfo(domain, None, socket.AF_INET):
                values.add(item[4][0])
        except Exception:
            pass
    return sorted(values)


def resolve_enabled(cfg: dict) -> dict[str, list[str]]:
    return {key: resolve_site(key) for key in enabled_sites(cfg)}


def build_ipset_restore(resolved: dict[str, list[str]]) -> str:
    lines = []
    for key, entries in resolved.items():
        name = f"{IPSET_PREFIX}{key.upper()}"
        lines.append(f"create {name} hash:net family inet hashsize 4096 maxelem 65536 -exist")
        lines.append(f"flush {name}")
        for entry in entries:
            lines.append(f"add {name} {entry}")
        lines.append("")
    return "\n".join(lines)
