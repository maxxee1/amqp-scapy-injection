# 🧃🐇 el_sniffer — MITM AMQP con Scapy (SOLO FINES EDUCATIVOS)

🚨 **Disclaimer:** entorno de laboratorio aislado. NO usar en redes ajenas.

Este contenedor es el **atacante**. Se mete en medio del tráfico AMQP entre el
productor (`el_enviador`) y el broker (`rabbit`) usando **ARP spoofing**, y
modifica el contenido de los mensajes en tránsito con **Scapy**.

## Qué hace `mitm.py`

1. Resuelve IP/MAC del productor y del broker.
2. Envenena sus cachés ARP (ARP spoofing) para situarse en medio.
3. Intercepta los frames AMQP (puerto 5672) y reemplaza marcadores en el
   payload **conservando la longitud** (así no rompe el framing TCP/AMQP):
   - `STATUS=NORMAL` → `STATUS=HACKED`
   - `note=legit` → `note=pwned`
4. Reenvía el paquete modificado a su destino real.
5. Al salir, **restaura** las tablas ARP de las víctimas.

## Modos (`MITM_MODE`)

- **`relay`** (por defecto): reenvío L2 en user-space con Scapy. Portable, no
  necesita módulos de kernel ni iptables. Funciona en WSL2 y Linux.
- **`nfqueue`**: `iptables -j NFQUEUE` + NetfilterQueue (técnica inline canónica).
  Requiere un kernel host con `nfnetlink_queue` (Kali/VM real, no siempre en WSL2).

## Configuración (vía variables de entorno, ver `.env`)

| Variable        | Default        | Descripción                          |
|-----------------|----------------|--------------------------------------|
| `MITM_TARGET_A` | `el_enviador`  | Víctima 1 (productor)                |
| `MITM_TARGET_B` | `rabbit`       | Víctima 2 (broker)                   |
| `MITM_MODE`     | `relay`        | `relay` o `nfqueue`                  |
| `AMQP_PORT`     | `5672`         | Puerto AMQP a interceptar            |
| `MITM_IFACE`    | `eth0`         | Interfaz de red del contenedor       |

## Privilegios

Necesita las capacidades `NET_ADMIN` y `NET_RAW` (definidas en
`docker-compose.yml`). **No** usa `privileged: true` (mínimo privilegio).

**SOLO LABORATORIO. SOLO PRUEBAS. NO A LAS ILEGALIDADES. 🫠🐇**
