from pathlib import Path

from app.core import dnsmasq
from app.core.constants import (
    BASE_DIR,
    HOSTS_MARKER_BEGIN,
    HOSTS_MARKER_END,
    IPSET_FILE,
    LOG_FILE,
    RULES_FILE,
    SITES,
)
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
    _emit(progress, "[OK] sysctl net.ipv4.ip_forward=1")

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
        _emit(progress, "[OK] ipset restore")

        _emit(progress, "Configurando dnsmasq")
        Path(dnsmasq.target_path()).write_text(dnsmasq.build_dnsmasq_config(enabled), encoding="utf-8")
        run(["systemctl", "restart", "dnsmasq"])
        _emit(progress, "[OK] dnsmasq configurado")
        _emit(progress, "Blindando /etc/hosts")
        _write_hosts_block(enabled)
        _emit(progress, "[OK] /etc/hosts actualizado")

    _emit(progress, "Generando iptables")
    rules_text = build_rules(cfg, resolved)
    Path(RULES_FILE).write_text(rules_text, encoding="utf-8")
    rc, _, err = run(["iptables-restore", "--test"], rules_text)
    if rc != 0:
        return False, f"iptables-restore --test fallo: {err.strip()}"
    _emit(progress, "[OK] iptables-restore --test")

    _emit(progress, "Aplicando iptables")
    rc, _, err = run(["iptables-restore"], rules_text)
    if rc != 0:
        return False, f"iptables-restore fallo: {err.strip()}"
    _emit(progress, "[OK] iptables-restore aplicado")

    run(["conntrack", "-F"])
    run(["resolvectl", "flush-caches"])
    run(["systemd-resolve", "--flush-caches"])
    _drop_ipv6(progress)
    status = firewall_status()
    _emit(progress, status["summary"])
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
    _clear_hosts_block()
    run(["systemctl", "restart", "dnsmasq"])
    for chain in ["INPUT", "FORWARD", "OUTPUT"]:
        run(["ip6tables", "-P", chain, "ACCEPT"])
    for table in ["filter"]:
        run(["ip6tables", "-t", table, "-F"])
        run(["ip6tables", "-t", table, "-X"])
    return True, "Cortafuegos apagado."


def firewall_status() -> dict:
    if not is_linux():
        return {"active": False, "summary": "Modo demo: sin iptables Linux.", "checks": {}}

    checks = {}
    rc, out, _ = run(["iptables", "-L", "PM_WEBBLOCK", "-n", "-v"])
    checks["PM_WEBBLOCK"] = rc == 0 and "PM_REJECT" in out
    rc, out, _ = run(["iptables", "-L", "OUTPUT", "-n", "-v"])
    checks["OUTPUT -> PM_WEBBLOCK"] = rc == 0 and "PM_WEBBLOCK" in out
    rc, out, _ = run(["iptables", "-L", "FORWARD", "-n", "-v"])
    checks["FORWARD -> PM_WEBBLOCK"] = rc == 0 and "PM_WEBBLOCK" in out
    rc, out, _ = run(["ipset", "list", "PM_YOUTUBE", "-terse"])
    checks["PM_YOUTUBE"] = rc == 0 and "Number of entries: 0" not in out
    checks["dnsmasq"] = Path(dnsmasq.target_path()).exists()
    checks["hosts"] = HOSTS_MARKER_BEGIN in Path("/etc/hosts").read_text(encoding="utf-8", errors="ignore") if Path("/etc/hosts").exists() else False
    active = all(checks.values())
    ok_count = sum(1 for value in checks.values() if value)
    summary = f"Estado real: {ok_count}/{len(checks)} verificaciones OK."
    return {"active": active, "summary": summary, "checks": checks}


def _drop_ipv6(progress=None) -> None:
    _emit(progress, "Bloqueando IPv6 para evitar bypass")
    for chain in ["INPUT", "FORWARD", "OUTPUT"]:
        run(["ip6tables", "-P", chain, "DROP"])


def _write_hosts_block(enabled: list[str]) -> None:
    hosts_path = Path("/etc/hosts")
    existing = hosts_path.read_text(encoding="utf-8", errors="ignore") if hosts_path.exists() else ""
    clean = _strip_hosts_block(existing)
    lines = [HOSTS_MARKER_BEGIN]
    for key in enabled:
        for domain in SITES[key]["domains"]:
            lines.append(f"0.0.0.0 {domain}")
    lines.append(HOSTS_MARKER_END)
    hosts_path.write_text(clean.rstrip() + "\n" + "\n".join(lines) + "\n", encoding="utf-8")


def _clear_hosts_block() -> None:
    hosts_path = Path("/etc/hosts")
    if not hosts_path.exists():
        return
    hosts_path.write_text(_strip_hosts_block(hosts_path.read_text(encoding="utf-8", errors="ignore")).rstrip() + "\n", encoding="utf-8")


def _strip_hosts_block(text: str) -> str:
    lines = []
    skipping = False
    for line in text.splitlines():
        if line.strip() == HOSTS_MARKER_BEGIN:
            skipping = True
            continue
        if line.strip() == HOSTS_MARKER_END:
            skipping = False
            continue
        if not skipping:
            lines.append(line)
    return "\n".join(lines)


def _emit(progress, msg: str) -> None:
    if progress:
        progress(msg)
