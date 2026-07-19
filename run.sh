#!/bin/bash
set -e
cd "$(dirname "$0")"

export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-xcb}"

if [[ $EUID -ne 0 ]]; then
  echo "[M-FIREWALL clean] Elevando permisos para iptables..."
  if command -v xhost >/dev/null 2>&1; then
    xhost +SI:localuser:root >/dev/null 2>&1 || true
  fi
  exec sudo env \
    DISPLAY="${DISPLAY:-:0}" \
    XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
    QT_QPA_PLATFORM="$QT_QPA_PLATFORM" \
    bash "$0" "$@"
fi

if [[ ! -f .venv/bin/activate ]]; then
  echo "Falta .venv. Ejecuta primero: sudo bash scripts/install.sh"
  exit 1
fi

source .venv/bin/activate
python3 run.py
