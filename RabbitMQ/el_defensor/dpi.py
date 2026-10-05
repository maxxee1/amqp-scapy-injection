"""
DPI defensivo (IDS casero) — SOLO LABORATORIO.

Observa de forma PASIVA el tráfico que entra/sale del broker (comparte su
network namespace, ver docker-compose.yml) y detecta los tres ataques del lab:

  - tamper : payload manipulado (firma STATUS=HACKED / note=pwned).
  - replay : un mismo mensaje (msg#ID) publicado más de una vez hacia el broker.
  - arp    : ARP spoofing (una IP cambia de MAC → alguien se metió en medio).

Cada alerta se EMPUJA por HTTP al panel (el_sniffer), que la muestra en la
sección 'Defensa'. No modifica ni inyecta nada: solo observa y avisa.
"""
import json
import os
import time
import urllib.request

from scapy.all import ARP, Ether, IP, Raw, TCP, sniff

IFACE = os.environ.get("DPI_IFACE", "eth0")
AMQP_PORT = int(os.environ.get("AMQP_PORT", "5672"))
SINK = os.environ.get("DEFENSE_SINK", "http://el_sniffer:8080/api/defense/alert")

TAMPER_SIGS = [b"STATUS=HACKED", b"note=pwned"]

seen_ids = {}        # msg#id -> ts (para detectar replay en publicaciones)
tampered_ids = set()  # ids ya alertados por manipulación
arp_table = {}       # ip -> mac (para detectar cambios)
arp_alerted = set()  # (ip, mac) conflictos ya alertados


def alert(atype, message):
    print(f"[DPI] {atype}: {message}", flush=True)
    try:
        data = json.dumps({"type": atype, "message": message}).encode()
        req = urllib.request.Request(
            SINK, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:  # noqa: BLE001
        print(f"[DPI] no pude reportar al panel: {e}", flush=True)


def extract_id(load: bytes):
    i = load.find(b"msg#")
    if i < 0:
        return None
    j = i + 4
    while j < len(load) and 48 <= load[j] <= 57:  # dígitos
        j += 1
    return load[i:j].decode("ascii", "replace") if j > i + 4 else None


def check_mapping(ip, mac, via):
    """Alerta si una IP empieza a aparecer con otra MAC (señal de MITM/ARP spoof)."""
    prev = arp_table.get(ip)
    if prev and prev != mac and (ip, mac) not in arp_alerted:
        arp_alerted.add((ip, mac))
        alert("arp", f"ARP spoofing: {ip} cambió de MAC {prev} a {mac} ({via})")
    arp_table[ip] = mac


def on_pkt(p):
    # --- ARP spoofing: por ARP reply explícito o por cambio de MAC en el tráfico ---
    if p.haslayer(ARP) and p[ARP].op == 2:  # ARP reply (is-at)
        check_mapping(p[ARP].psrc, p[ARP].hwsrc, "ARP reply")
        return
    if p.haslayer(Ether) and p.haslayer(IP):
        check_mapping(p[IP].src, p[Ether].src, "tráfico")

    # --- AMQP (payload en claro) ---
    if not (p.haslayer(TCP) and p.haslayer(Raw)):
        return
    load = bytes(p[Raw].load)
    mid = extract_id(load)

    # Manipulación (en cualquier dirección; se avisa una vez por mensaje)
    if any(s in load for s in TAMPER_SIGS):
        if mid and mid not in tampered_ids:
            tampered_ids.add(mid)
            alert("tamper", f"Payload manipulado detectado en {mid}")
        elif not mid:
            alert("tamper", "Payload manipulado detectado")

    # Replay: solo publicaciones hacia el broker (dport = AMQP) con id repetido
    if mid and p[TCP].dport == AMQP_PORT:
        if mid in seen_ids:
            alert("replay", f"Posible replay: {mid} publicado de nuevo")
        else:
            seen_ids[mid] = time.time()
            if len(seen_ids) > 5000:   # cota de memoria
                seen_ids.clear()


def main():
    print(f"[DPI] escuchando en {IFACE} (netns del broker), puerto {AMQP_PORT}",
          flush=True)
    alert("info", "DPI iniciado: monitoreando el broker")
    sniff(iface=IFACE, prn=on_pkt, store=0)


if __name__ == "__main__":
    main()
