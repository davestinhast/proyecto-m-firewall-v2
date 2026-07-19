import webbrowser

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.config import load_config, save_config
from app.core.constants import APP_NAME, APP_VERSION, LOG_FILE, SITES
from app.core.firewall import apply_firewall, firewall_status, stop_firewall
from app.core.network import own_ip_and_iface


class ApplyWorker(QThread):
    progress = Signal(str)
    finished = Signal(bool, str)

    def __init__(self, cfg: dict):
        super().__init__()
        self.cfg = cfg

    def run(self):
        ok, msg = apply_firewall(self.cfg, self.progress.emit)
        self.finished.emit(ok, msg)


class StopWorker(QThread):
    finished = Signal(bool, str)

    def run(self):
        ok, msg = stop_firewall()
        self.finished.emit(ok, msg)


class StatusWorker(QThread):
    finished = Signal(dict)

    def run(self):
        self.finished.emit(firewall_status())


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.worker = None
        self.stop_worker = None
        self.status_worker = None
        self.firewall_active = False
        self.checks: dict[str, QCheckBox] = {}
        self.site_status_labels: dict[str, QLabel] = {}
        self.status_items: dict[str, QLabel] = {}
        self.conn_checks: list[QCheckBox] = []
        self.conn_ports: list[QLineEdit] = []
        self.conn_max: list[QLineEdit] = []
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1120, 760)
        self._load_styles()
        self._build()
        self._refresh_detected()
        self._refresh_status()

    def _load_styles(self):
        from pathlib import Path
        qss = Path(__file__).resolve().parents[1] / "resources" / "styles" / "main.qss"
        if qss.exists():
            self.setStyleSheet(qss.read_text(encoding="utf-8"))

    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        header = QFrame()
        header.setObjectName("card")
        h = QHBoxLayout(header)
        title = QLabel(f"{APP_NAME}")
        title.setStyleSheet("font-size: 18px; font-weight: 800; color: #3b82f6; background: transparent;")
        h.addWidget(title)
        self.detected_lbl = QLabel("")
        self.detected_lbl.setObjectName("label_secondary")
        h.addWidget(self.detected_lbl)
        h.addStretch()
        version = QLabel(APP_VERSION)
        version.setObjectName("label_hint")
        h.addWidget(version)
        layout.addWidget(header)

        tabs = QTabWidget()
        tabs.addTab(self._sites_card(), "Sitios Web")
        tabs.addTab(self._network_tab(), "Reglas de Red")
        tabs.addTab(self._logs_tab(), "Registros")
        layout.addWidget(tabs, stretch=2)

        console_card = QFrame()
        console_card.setObjectName("card")
        c = QVBoxLayout(console_card)
        c.addWidget(QLabel("Consola"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(220)
        c.addWidget(self.console)
        layout.addWidget(console_card, stretch=1)

        footer = QHBoxLayout()
        self.status_lbl = QLabel("Listo.")
        self.status_lbl.setObjectName("label_secondary")
        footer.addWidget(self.status_lbl, stretch=1)
        stop_btn = QPushButton("Apagar Cortafuegos")
        stop_btn.setObjectName("btn_danger")
        stop_btn.clicked.connect(self._stop)
        footer.addWidget(stop_btn)
        apply_btn = QPushButton("Guardar y Activar")
        apply_btn.setObjectName("btn_apply")
        apply_btn.clicked.connect(self._apply)
        self.apply_btn = apply_btn
        footer.addWidget(apply_btn)
        layout.addLayout(footer)

    def _sites_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        label = QLabel("Bloqueo de sitios")
        label.setObjectName("label_title")
        layout.addWidget(label)
        layout.addWidget(self._status_card())
        for key, site in SITES.items():
            row = QFrame()
            row.setObjectName("card")
            r = QHBoxLayout(row)
            name = QLabel(site["label"])
            name.setStyleSheet("font-size: 15px; font-weight: 700; background: transparent;")
            r.addWidget(name)
            domains = QLabel("  ·  ".join(site["domains"][:5]))
            domains.setObjectName("label_hint")
            r.addWidget(domains, stretch=1)
            check = QCheckBox("Habilitar")
            check.setChecked(self.cfg.get("sites", {}).get(key, {}).get("enabled", False))
            self.checks[key] = check
            r.addWidget(check)
            status = QLabel("Pendiente")
            status.setMinimumWidth(90)
            status.setStyleSheet("color: #f59e0b; font-size: 12px; font-weight: 700; background: transparent;")
            self.site_status_labels[key] = status
            r.addWidget(status)
            open_btn = QPushButton(self._site_button_text(key))
            open_btn.setObjectName("btn_secondary")
            open_btn.setToolTip(f"Abrir {site['label']} para probar el bloqueo.")
            open_btn.clicked.connect(lambda _, domain=site["domains"][0]: webbrowser.open(f"https://{domain}"))
            r.addWidget(open_btn)
            layout.addWidget(row)
        hint = QLabel("Despues de activar, la app verifica cadenas, ipset, DNS local y hosts automaticamente.")
        hint.setObjectName("label_hint")
        layout.addWidget(hint)
        return frame

    def _status_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        title = QLabel("Estado real del cortafuegos")
        title.setObjectName("label_subtitle")
        layout.addWidget(title)
        grid = QHBoxLayout()
        for name in ["PM_WEBBLOCK", "OUTPUT -> PM_WEBBLOCK", "FORWARD -> PM_WEBBLOCK", "PM_YOUTUBE", "dnsmasq", "hosts"]:
            lbl = QLabel(f"{name}: -")
            lbl.setObjectName("label_mono")
            lbl.setMinimumWidth(150)
            self.status_items[name] = lbl
            grid.addWidget(lbl)
        layout.addLayout(grid)
        row = QHBoxLayout()
        verify = QPushButton("Verificar estado")
        verify.setObjectName("btn_secondary")
        verify.clicked.connect(self._refresh_status)
        row.addWidget(verify)
        row.addStretch()
        layout.addLayout(row)
        return frame

    def _site_button_text(self, key: str) -> str:
        labels = {"facebook": "[FB] Abrir", "hotmail": "[HM] Abrir", "youtube": "[YT] Abrir"}
        return labels.get(key, "Abrir")

    def _network_tab(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(12)
        left = QVBoxLayout()
        right = QVBoxLayout()
        left.addWidget(self._settings_card())
        left.addWidget(self._client_server_card())
        right.addWidget(self._mac_card())
        right.addWidget(self._connlimit_card())
        layout.addLayout(left, stretch=1)
        layout.addLayout(right, stretch=1)
        return page

    def _settings_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        title = QLabel("Red")
        title.setObjectName("label_title")
        layout.addWidget(title)
        form = QFormLayout()
        self.wan_input = QComboBox()
        self.lan_input = QComboBox()
        for iface in ["eth0", "eth1", "wlan0", "enp0s3"]:
            self.wan_input.addItem(iface)
            self.lan_input.addItem(iface)
        self.server_ip_input = QLineEdit()
        self.server_ip_input.setPlaceholderText("IP de Kali, ej. 192.168.100.144")
        self.gateway_lbl = QLabel("")
        self.gateway_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("WAN:", self.wan_input)
        form.addRow("LAN:", self.lan_input)
        form.addRow("IP Kali:", self.server_ip_input)
        form.addRow("Cliente:", self.gateway_lbl)
        layout.addLayout(form)
        detect = QPushButton("Detectar IP")
        detect.setObjectName("btn_secondary")
        detect.clicked.connect(self._refresh_detected)
        layout.addWidget(detect)
        layout.addStretch()

        if self.cfg.get("interfaces", {}).get("wan"):
            self.wan_input.setCurrentText(self.cfg["interfaces"]["wan"])
        if self.cfg.get("interfaces", {}).get("lan"):
            self.lan_input.setCurrentText(self.cfg["interfaces"]["lan"])
        self.server_ip_input.setText(self.cfg.get("server_ip", ""))
        self.server_ip_input.textChanged.connect(self._update_gateway_text)
        self._update_gateway_text()
        return frame

    def _client_server_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        title = QLabel("Cliente -> Servidor")
        title.setObjectName("label_title")
        layout.addWidget(title)
        self.clisrv_enabled = QCheckBox("Bloquear paquetes del cliente al servidor")
        clisrv = self.cfg.get("client_server", {})
        self.clisrv_enabled.setChecked(clisrv.get("enabled", False))
        layout.addWidget(self.clisrv_enabled)
        form = QFormLayout()
        self.clisrv_client = QLineEdit()
        self.clisrv_client.setPlaceholderText("IP cliente, ej. 192.168.100.50")
        self.clisrv_server = QLineEdit()
        self.clisrv_server.setPlaceholderText("IP servidor, vacio = IP Kali")
        self.clisrv_client.setText(clisrv.get("client_ip", ""))
        self.clisrv_server.setText(clisrv.get("server_ip", ""))
        form.addRow("Cliente:", self.clisrv_client)
        form.addRow("Servidor:", self.clisrv_server)
        layout.addLayout(form)
        hint = QLabel("El servidor queda autorizado a enviar/iniciar paquetes hacia el cliente.")
        hint.setObjectName("label_hint")
        layout.addWidget(hint)
        return frame

    def _mac_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        title = QLabel("Bloqueo MAC")
        title.setObjectName("label_title")
        layout.addWidget(title)
        rule = (self.cfg.get("mac_rules") or [{}])[0]
        self.mac_enabled = QCheckBox("Bloquear equipo por direccion MAC")
        self.mac_enabled.setChecked(rule.get("enabled", False))
        layout.addWidget(self.mac_enabled)
        form = QFormLayout()
        self.mac_name = QLineEdit()
        self.mac_name.setText(rule.get("name", "Cliente"))
        self.mac_addr = QLineEdit()
        self.mac_addr.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.mac_addr.setText(rule.get("mac", ""))
        form.addRow("Nombre:", self.mac_name)
        form.addRow("MAC:", self.mac_addr)
        layout.addLayout(form)
        hint = QLabel("Se aplica en FORWARD sobre la interfaz LAN configurada.")
        hint.setObjectName("label_hint")
        layout.addWidget(hint)
        return frame

    def _connlimit_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        title = QLabel("Limite de conexiones")
        title.setObjectName("label_title")
        layout.addWidget(title)
        self.conn_checks = []
        self.conn_ports = []
        self.conn_max = []
        for item in self.cfg.get("connection_limits", []):
            row = QFrame()
            row.setObjectName("card")
            r = QHBoxLayout(row)
            check = QCheckBox(item.get("name", "Puerto"))
            check.setChecked(item.get("enabled", False))
            port = QLineEdit(str(item.get("port", "")))
            port.setFixedWidth(70)
            max_conn = QLineEdit(str(item.get("max", "")))
            max_conn.setFixedWidth(70)
            r.addWidget(check)
            r.addWidget(QLabel("Puerto"))
            r.addWidget(port)
            r.addWidget(QLabel("Max"))
            r.addWidget(max_conn)
            r.addStretch()
            layout.addWidget(row)
            self.conn_checks.append(check)
            self.conn_ports.append(port)
            self.conn_max.append(max_conn)
        return frame

    def _logs_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        card = QFrame()
        card.setObjectName("card")
        c = QVBoxLayout(card)
        title = QLabel("Paquetes rechazados")
        title.setObjectName("label_title")
        c.addWidget(title)
        self.logs_view = QTextEdit()
        self.logs_view.setReadOnly(True)
        self.logs_view.setMinimumHeight(360)
        c.addWidget(self.logs_view)
        row = QHBoxLayout()
        refresh = QPushButton("Actualizar registros")
        refresh.setObjectName("btn_secondary")
        refresh.clicked.connect(self._load_logs)
        row.addWidget(refresh)
        row.addStretch()
        c.addLayout(row)
        layout.addWidget(card)
        return page

    def _refresh_detected(self):
        ip, iface = own_ip_and_iface()
        self.detected_lbl.setText(f"IP detectada: {ip}   |   Interfaz: {iface}")
        if ip != "127.0.0.1":
            self.server_ip_input.setText(ip)
            self.wan_input.setCurrentText(iface)
            self.lan_input.setCurrentText(iface)

    def _update_gateway_text(self):
        ip = self.server_ip_input.text().strip() or "IP_DE_KALI"
        self.gateway_lbl.setText(f"sudo ip route replace default via {ip}")

    def _save_from_ui(self) -> bool:
        self.cfg.setdefault("interfaces", {})
        self.cfg["interfaces"]["wan"] = self.wan_input.currentText()
        self.cfg["interfaces"]["lan"] = self.lan_input.currentText()
        self.cfg["server_ip"] = self.server_ip_input.text().strip()
        self.cfg.setdefault("sites", {})
        for key, check in self.checks.items():
            self.cfg["sites"].setdefault(key, {})
            self.cfg["sites"][key]["enabled"] = check.isChecked()
        self.cfg["client_server"] = {
            "enabled": self.clisrv_enabled.isChecked(),
            "client_ip": self.clisrv_client.text().strip(),
            "server_ip": self.clisrv_server.text().strip(),
            "protocols": ["tcp", "udp", "icmp"],
        }
        self.cfg["mac_rules"] = [{
            "name": self.mac_name.text().strip() or "Cliente",
            "mac": self.mac_addr.text().strip(),
            "enabled": self.mac_enabled.isChecked(),
        }]
        current_limits = self.cfg.get("connection_limits", [])
        updated_limits = []
        for idx, item in enumerate(current_limits):
            updated = dict(item)
            updated["enabled"] = self.conn_checks[idx].isChecked()
            try:
                updated["port"] = int(self.conn_ports[idx].text().strip() or 0)
                updated["max"] = int(self.conn_max[idx].text().strip() or 0)
            except ValueError:
                QMessageBox.warning(self, "M-FIREWALL", "Puerto y Max deben ser numeros enteros.")
                return False
            updated_limits.append(updated)
        self.cfg["connection_limits"] = updated_limits
        save_config(self.cfg)
        return True

    def _apply(self):
        if not self._save_from_ui():
            return
        self.console.clear()
        self._log("Guardado config. Aplicando firewall...")
        self.apply_btn.setEnabled(False)
        self.worker = ApplyWorker(self.cfg)
        self.worker.progress.connect(self._log)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _stop(self):
        self._log("Apagando firewall...")
        self.stop_worker = StopWorker()
        self.stop_worker.finished.connect(self._done)
        self.stop_worker.start()

    def _done(self, ok: bool, msg: str):
        self.apply_btn.setEnabled(True)
        self.status_lbl.setText(msg)
        self._log(msg)
        self._load_logs()
        self._refresh_status()
        if not ok:
            QMessageBox.warning(self, "M-FIREWALL", msg)

    def _log(self, msg: str):
        self.console.append(msg)

    def _load_logs(self):
        from pathlib import Path
        path = Path(LOG_FILE)
        if not path.exists():
            self.logs_view.setPlainText("Aun no existe el archivo de registros.")
            return
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        self.logs_view.setPlainText("\n".join(lines[-250:]))

    def _refresh_status(self):
        if self.status_worker and self.status_worker.isRunning():
            return
        self.status_worker = StatusWorker()
        self.status_worker.finished.connect(self._on_status)
        self.status_worker.start()

    def _on_status(self, data: dict):
        checks = data.get("checks", {})
        self.firewall_active = bool(data.get("active"))
        self.status_lbl.setText(data.get("summary", "Estado no disponible."))
        for name, lbl in self.status_items.items():
            ok = checks.get(name, False)
            lbl.setText(f"{name}: {'OK' if ok else 'NO'}")
            color = "#22c55e" if ok else "#ef4444"
            lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 700; background: transparent;")
        youtube_ok = checks.get("PM_YOUTUBE", False) and checks.get("PM_WEBBLOCK", False)
        web_ok = checks.get("PM_WEBBLOCK", False)
        for key, lbl in self.site_status_labels.items():
            enabled = self.checks[key].isChecked()
            ok = youtube_ok if key == "youtube" else web_ok
            if enabled and ok:
                lbl.setText("Activo")
                lbl.setStyleSheet("color: #22c55e; font-size: 12px; font-weight: 700; background: transparent;")
            elif enabled:
                lbl.setText("Falta")
                lbl.setStyleSheet("color: #ef4444; font-size: 12px; font-weight: 700; background: transparent;")
            else:
                lbl.setText("Apagado")
                lbl.setStyleSheet("color: #8892a4; font-size: 12px; font-weight: 700; background: transparent;")

    def closeEvent(self, event):
        if not self.firewall_active:
            event.accept()
            return
        reply = QMessageBox.question(
            self,
            "Cerrar M-FIREWALL",
            "El cortafuegos sigue activo.\n\n¿Quieres restaurar la red a valores predeterminados antes de cerrar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes,
        )
        if reply == QMessageBox.StandardButton.Cancel:
            event.ignore()
            return
        if reply == QMessageBox.StandardButton.Yes:
            ok, msg = stop_firewall()
            self.status_lbl.setText(msg)
            if not ok:
                QMessageBox.warning(self, "M-FIREWALL", msg)
                event.ignore()
                return
        event.accept()
