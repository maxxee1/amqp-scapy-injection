# 🕷️ el_sniffer — MITM AMQP + panel de control (SOLO LABORATORIO)

🚨 **Disclaimer:** entorno aislado, fines educativos. No usar en redes ajenas.

El atacante: se mete en medio del tráfico AMQP (`el_enviador` ⇄ `rabbit`) con
**ARP spoofing** y puede **leer y modificar** los mensajes en tránsito. Todo se
controla desde un **panel web** (estilo Horizon UI) o por su **API REST**.

## Componentes

| Archivo | Rol |
|---|---|
| `engine.py` | Motor MITM: ARP spoof, relay L2, reglas, stats, eventos (en hilos). |
| `app.py` | API Flask + sirve el panel. Punto de entrada del contenedor. |
| `static/index.html` | Panel de control (vanilla JS, diseño Horizon). |

## Panel

Con el stack arriba: **http://localhost:8080**

Flujo pensado: arranca **apagado** → prendes el MITM en modo **Leer** (ves el
tráfico sin tocarlo) → cambias a **Editar**, defines las reglas y desde ahí
modifica automáticamente. (No se edita en vivo mensaje a mensaje: se
pre-configura la regla, para no provocar timeouts en la conexión.)

## API REST

| Método | Ruta | Cuerpo | Qué hace |
|---|---|---|---|
| GET  | `/api/status` | — | Estado completo (on/off, modo, reglas, stats, víctimas). |
| POST | `/api/attack` | `{"on": true}` | Prende/apaga el ARP spoofing. |
| POST | `/api/mode`   | `{"mode": "read"\|"edit"}` | Cambia el modo. |
| POST | `/api/rules`  | `{"rules": [{"match": "...", "replace": "..."}]}` | Define las sustituciones. |
| GET  | `/api/events` | — | Últimos mensajes vistos/modificados (feed). |

Las reglas son **de igual longitud**: el reemplazo se ajusta (trunca o rellena)
al tamaño exacto del texto buscado, para no desincronizar el stream TCP/AMQP.

## Variables de entorno (ver `.env`)

| Variable | Default | Descripción |
|---|---|---|
| `MITM_TARGET_A` | `el_enviador` | Víctima 1 (productor) |
| `MITM_TARGET_B` | `rabbit` | Víctima 2 (broker) |
| `AMQP_PORT` | `5672` | Puerto AMQP a interceptar |
| `MITM_IFACE` | `eth0` | Interfaz de red del contenedor |

## Privilegios

Capacidades `NET_ADMIN` + `NET_RAW` (no `privileged`). Mínimo privilegio.

**SOLO LABORATORIO. SOLO PRUEBAS. 🐇**
