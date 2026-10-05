#!/bin/sh
# Corre Suricata en primer plano con nuestras reglas. SOLO LABORATORIO.
IFACE="${SURI_IFACE:-eth0}"
mkdir -p /var/log/suricata
: > /var/log/suricata/eve.json 2>/dev/null || true

echo "[suricata] iniciando IDS en interfaz $IFACE con reglas locales..."
exec suricata -i "$IFACE" -S /rules/local.rules -l /var/log/suricata
