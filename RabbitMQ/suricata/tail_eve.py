"""
Tailer de eve.json: lee las alertas de Suricata y las empuja al panel
(el_sniffer), igual que hace el DPI. SOLO LABORATORIO.
"""
import json
import os
import time
import urllib.request

EVE = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
SINK = os.environ.get("DEFENSE_SINK", "http://el_sniffer:8080/api/defense/alert")


def forward(message):
    try:
        data = json.dumps({"type": "suricata", "message": message}).encode()
        req = urllib.request.Request(
            SINK, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:  # noqa: BLE001
        print(f"[suricata-tail] no pude reportar al panel: {e}", flush=True)


def main():
    while not os.path.exists(EVE):
        time.sleep(1)
    forward("Suricata IDS activo: vigilando el broker")
    with open(EVE) as f:
        f.seek(0, 2)  # al final del archivo
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("event_type") == "alert":
                sig = ev.get("alert", {}).get("signature", "alerta Suricata")
                print(f"[suricata-tail] {sig}", flush=True)
                forward(sig)


if __name__ == "__main__":
    main()
