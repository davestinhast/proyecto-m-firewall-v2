from app.core.constants import DNSMASQ_FILE, SITES


def build_dnsmasq_config(enabled: list[str]) -> str:
    lines = [
        "# M-FIREWALL clean",
        "# Devuelve 0.0.0.0 para dominios bloqueados.",
        "listen-address=0.0.0.0",
        "bind-interfaces",
    ]
    for key in enabled:
        for domain in SITES[key]["domains"]:
            lines.append(f"address=/{domain}/0.0.0.0")
    return "\n".join(lines) + "\n"


def target_path() -> str:
    return DNSMASQ_FILE
