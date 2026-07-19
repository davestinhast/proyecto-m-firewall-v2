#!/bin/bash
echo "=== M-FIREWALL clean diagnostico ==="
date
echo

echo "[Red]"
ip -br addr 2>/dev/null || true
ip route 2>/dev/null || true
echo

echo "[Config]"
cat /opt/proyecto-m-clean/config/firewall.json 2>/dev/null || cat config/firewall.example.json
echo

echo "[ipset]"
for s in PM_FACEBOOK PM_HOTMAIL PM_YOUTUBE; do
  echo "--- $s ---"
  ipset list "$s" -terse 2>&1 || true
done
echo

echo "[iptables]"
for chain in INPUT OUTPUT FORWARD PM_WEBBLOCK PM_CLISRV PM_MACBLOCK PM_CONNLIMIT PM_REJECT; do
  echo "--- $chain ---"
  iptables -L "$chain" -n -v --line-numbers 2>&1 || true
done
echo

echo "[nat]"
iptables -t nat -L PREROUTING -n -v --line-numbers 2>&1 || true
iptables -t nat -L POSTROUTING -n -v --line-numbers 2>&1 || true
echo

echo "[dnsmasq]"
systemctl is-active dnsmasq 2>&1 || true
cat /etc/dnsmasq.d/proyecto-m-youtube.conf 2>/dev/null || true
echo

echo "[DNS]"
for d in youtube.com youtubei.googleapis.com googlevideo.com yt3.ggpht.com; do
  echo "--- $d ---"
  getent ahostsv4 "$d" | head -10 || true
done
echo

echo "[Logs]"
tail -80 /var/log/proyecto-m-clean/rejected.log 2>/dev/null || true
echo

echo "[Archivo personalizado de reglas]"
ls -l /opt/proyecto-m-clean/rules/project_m.rules.v4 2>/dev/null || true
head -40 /opt/proyecto-m-clean/rules/project_m.rules.v4 2>/dev/null || true
echo "=== fin ==="
