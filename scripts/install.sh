#!/bin/bash
set -e

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Este instalador requiere Kali/Linux."
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta: sudo bash scripts/install.sh"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASE="/opt/proyecto-m-clean"

apt-get update
apt-get install -y python3 python3-venv python3-pip iptables ipset dnsmasq conntrack rsyslog

cd "$ROOT_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

mkdir -p "$BASE/config" "$BASE/rules" /var/log/proyecto-m-clean
if [[ ! -f "$BASE/config/firewall.json" ]]; then
  cp "$ROOT_DIR/config/firewall.example.json" "$BASE/config/firewall.json"
fi
touch /var/log/proyecto-m-clean/rejected.log

cat >/etc/rsyslog.d/30-proyecto-m-clean.conf <<'EOF'
:msg, contains, "PM-DROP " /var/log/proyecto-m-clean/rejected.log
& stop
EOF
systemctl restart rsyslog || true

chmod +x "$ROOT_DIR/run.sh" "$ROOT_DIR/scripts/diagnose.sh"

echo "Instalado. Ejecuta:"
echo "  cd $ROOT_DIR"
echo "  ./run.sh"
