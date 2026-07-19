from datetime import datetime

from app.core.constants import (
    CHAIN_CLISRV,
    CHAIN_CONNLIMIT,
    CHAIN_MAC,
    CHAIN_REJECT,
    CHAIN_WEB,
    IPSET_PREFIX,
    RULES_FILE,
    SITES,
)


def build_rules(cfg: dict, resolved: dict[str, list[str]]) -> str:
    wan = cfg.get("interfaces", {}).get("wan") or "eth0"
    lan = cfg.get("interfaces", {}).get("lan") or ""
    server_ip = cfg.get("server_ip", "")
    action = cfg.get("default_action", "DROP")
    iface = f"-i {lan} " if lan else ""

    lines = [
        f"# M-FIREWALL clean - generado {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"# Guardado esperado: {RULES_FILE}",
        "*nat",
        ":PREROUTING ACCEPT [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        ":POSTROUTING ACCEPT [0:0]",
    ]
    if server_ip:
        lines += [
            f"-A PREROUTING {iface}-p udp --dport 53 -j DNAT --to-destination {server_ip}:53",
            f"-A PREROUTING {iface}-p tcp --dport 53 -j DNAT --to-destination {server_ip}:53",
        ]
    lines += [
        f"-A POSTROUTING -o {wan} -j MASQUERADE",
        "COMMIT",
        "",
        "*filter",
        f":{CHAIN_WEB} - [0:0]",
        f":{CHAIN_CLISRV} - [0:0]",
        f":{CHAIN_MAC} - [0:0]",
        f":{CHAIN_CONNLIMIT} - [0:0]",
        f":{CHAIN_REJECT} - [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        f"-A {CHAIN_REJECT} -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix \"PM-DROP \" --log-level 4",
        f"-A {CHAIN_REJECT} -j {action}",
        "",
    ]

    mac_rules = cfg.get("mac_rules", [])
    active_macs = [rule for rule in mac_rules if rule.get("enabled") and rule.get("mac")]
    if active_macs:
        lines.append("# Bloqueo por direccion MAC de equipos clientes")
        for rule in active_macs:
            name = rule.get("name", "Cliente")
            mac = rule["mac"].strip()
            lines.append(f"# MAC {name}: {mac}")
            lines.append(f"-A {CHAIN_MAC} {iface}-m mac --mac-source {mac} -j {CHAIN_REJECT}")
        lines.append("")

    clisrv = cfg.get("client_server", {})
    if clisrv.get("enabled") and clisrv.get("client_ip"):
        client_ip = clisrv["client_ip"].strip()
        target_server = (clisrv.get("server_ip") or server_ip).strip()
        protocols = clisrv.get("protocols") or ["tcp", "udp", "icmp"]
        if target_server:
            lines += [
                "# Bloqueo unidireccional cliente -> servidor",
                "# El servidor conserva permiso para iniciar/enviar paquetes al cliente.",
                f"-A {CHAIN_CLISRV} {iface}-s {target_server} -d {client_ip} -j ACCEPT",
                f"-A {CHAIN_CLISRV} {iface}-s {client_ip} -d {target_server} -m state --state ESTABLISHED,RELATED -j ACCEPT",
            ]
            for proto in protocols:
                proto_flag = "" if proto == "all" else f"-p {proto} "
                state_flag = "" if proto == "icmp" else "-m state --state NEW "
                lines.append(f"-A {CHAIN_CLISRV} {iface}{proto_flag}-s {client_ip} -d {target_server} {state_flag}-j {CHAIN_REJECT}")
            lines.append("")

    conn_limits = cfg.get("connection_limits", [])
    active_limits = [item for item in conn_limits if item.get("enabled") and int(item.get("port") or 0) > 0]
    if active_limits:
        lines.append("# Limite de conexiones simultaneas por IP cliente")
        for item in active_limits:
            proto = item.get("proto", "tcp")
            port = int(item.get("port"))
            max_conn = int(item.get("max") or 10)
            name = item.get("name", f"{proto}/{port}")
            lines.append(f"# {name}: max {max_conn} conexiones simultaneas")
            lines.append(
                f"-A {CHAIN_CONNLIMIT} {iface}-p {proto} --dport {port} "
                f"-m connlimit --connlimit-above {max_conn} --connlimit-mask 32 "
                f"-j {CHAIN_REJECT}"
            )
        lines.append("")

    for key in resolved:
        set_name = f"{IPSET_PREFIX}{key.upper()}"
        label = SITES[key]["label"]
        lines += [
            f"# {label}",
            f"-A {CHAIN_WEB} -m set --match-set {set_name} dst -j {CHAIN_REJECT}",
        ]
        for keyword in SITES[key]["keywords"]:
            lines.append(
                f"-A {CHAIN_WEB} -p tcp --dport 443 -m string --string \"{keyword}\" --algo bm --to 65535 -j {CHAIN_REJECT}"
            )

    if "youtube" in resolved:
        lines += [
            "# Anti-evasion YouTube: QUIC/HTTP3 y DNS cifrado",
            f"-A {CHAIN_WEB} -p udp --dport 443 -j {CHAIN_REJECT}",
            f"-A {CHAIN_WEB} -p tcp --dport 853 -j {CHAIN_REJECT}",
            f"-A {CHAIN_WEB} -p udp --dport 853 -j {CHAIN_REJECT}",
        ]

    lines += [
        "",
        f"-A INPUT -j {CHAIN_WEB}",
        f"-A OUTPUT -j {CHAIN_WEB}",
        f"-A FORWARD {iface}-j {CHAIN_MAC}",
        f"-A FORWARD {iface}-j {CHAIN_CLISRV}",
        f"-A FORWARD {iface}-j {CHAIN_CONNLIMIT}",
        f"-A FORWARD {iface}-j {CHAIN_WEB}",
        "COMMIT",
        "",
    ]
    return "\n".join(lines)
