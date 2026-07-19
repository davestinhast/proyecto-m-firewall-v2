from pathlib import Path

from app.core import dnsmasq
from app.core.constants import BASE_DIR, CONFIG_FILE, IPSET_FILE, LOG_FILE, RULES_FILE
from app.core.domains import build_ipset_restore, enabled_sites, resolve_enabled
from app.core.network import is_linux, is_root, run
from app.core.rules import build_rules


def apply_firewall(cfg: dict, progress=None) -> tuple[bool, str]:
    if not is_linux() or not is_root():
        return False, "Ejecuta en Kali/Linux con sudo."

    enabled = enabled_sites(cfg)
    has_mac = any(rule.get("enabled") and rule.get("mac") for rule in cfg.get("mac_rules", []))
    has_clisrv = bool(cfg.get("client_server", {}).get("enabled") and cfg.get("client_server", {}).get("client_ip"))
    has_connlimit = any(rule.get("enabled") and int(rule.get("port") or 0) > 0 for rule in cfg.get("connection_limits", []))
    if not any([enabled, has_mac, has_clisrv, has_connlimit]):
        return False, "No hay reglas habilitadas."

    _emit(progress, "Preparando carpetas")
    Path(BASE_DIR, "config").mkdir(parents=True, exist_ok=True)
    Path(BASE_DIR, "rules").mkdir(parents=True, exist_ok=True)
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

    _emit(progress, "Activando IP forwarding")
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    resolved = {}
    if enabled:
        _emit(progress, "Resolviendo dominios")
        resolved = resolve_enabled(cfg)

        _emit(progress, "Cargando ipset")
        ipset_text = build_ipset_restore(resolved)
        Path(IPSET_FILE).write_text(ipset_text, encoding="utf-8")
        rc, _, err = run(["ipset", "restore"], ipset_text)
        if rc != 0:
            return False, f"ipset fallo: {err.strip()}"

        _emit(progress, "Configurando dnsmasq")
        Path(dnsmasq.target_path()).write_text(dnsmasq.build_dnsmasq_config(enabled), encoding="utf-8")
        run(["systemctl", "restart", "dnsmasq"])

    _emit(progress, "Generando iptables")
    rules_text = build_rules(cfg, resolved)
    Path(RULES_FILE).write_text(rules_text, encoding="utf-8")
    rc, _, err = run(["iptables-restore", "--test"], rules_text)
    if rc != 0:
        return False, f"iptables-restore --test fallo: {err.strip()}"

    _emit(progress, "Aplicando iptables")
    rc, _, err = run(["iptables-restore"], rules_text)
    if rc != 0:
        return False, f"iptables-restore fallo: {err.strip()}"

    run(["conntrack", "-F"])
    return True, f"Cortafuegos activo. Sitios: {', '.join(enabled)}"


def stop_firewall() -> tuple[bool, str]:
    if not is_linux() or not is_root():
        return False, "Ejecuta en Kali/Linux con sudo."
    for table in ["filter", "nat"]:
        run(["iptables", "-t", table, "-F"])
        run(["iptables", "-t", table, "-X"])
    for chain in ["INPUT", "FORWARD", "OUTPUT"]:
        run(["iptables", "-P", chain, "ACCEPT"])
    run(["ipset", "destroy"])
    try:
        Path(dnsmasq.target_path()).unlink(missing_ok=True)
    except Exception:
        pass
    run(["systemctl", "restart", "dnsmasq"])
    return True, "Cortafuegos apagado."


def _emit(progress, msg: str) -> None:
    if progress:
        progress(msg)
