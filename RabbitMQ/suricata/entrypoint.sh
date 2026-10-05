#!/bin/sh
# Arranca Suricata en segundo plano y el tailer en primer plano. SOLO LABORATORIO.
set -e

IFACE="${SURI_IFACE:-eth0}"
mkdir -p /var/log/suricata
: > /var/log/suricata/eve.json 2>/dev/null || true

echo "[suricata] iniciando IDS en interfaz $IFACE con reglas locales..."
suricata -i "$IFACE" -S /rules/local.rules -l /var/log/suricata &

# Reenvía las alertas de eve.json al panel
exec python3 /tail_eve.py
