# AMQP Scapy Injection — Laboratorio de Ataque y Defensa 🕷️🐇

Laboratorio **reproducible** para aprender a **interceptar, modificar e inyectar**
tráfico **AMQP** (RabbitMQ) mediante un ataque **Man-in-the-Middle con ARP
spoofing** real entre contenedores Docker — todo controlado desde un **panel web**.

> ⚠️ **SOLO USO EDUCATIVO / LABORATORIO AISLADO.**
> Corre en una red Docker privada. No lo uses nunca contra redes o equipos
> ajenos. Es un entorno de práctica para entender estos ataques y cómo defenderse.

---

## 🧩 Arquitectura

```
                      red_docker (bridge L2 aislada)
   ┌────────────┐        ARP spoofing        ┌─────────────┐
   │ el_enviador│◄──────────────────────────►│   rabbit    │
   │ (productor)│      tráfico AMQP :5672     │  (RabbitMQ) │
   └─────┬──────┘       (interceptado)        └──────┬──────┘
         │                                           │
         │            ┌────────────────────┐         │
         └───────────►│     el_sniffer     │◄────────┘
                      │  motor MITM (Scapy)│   se mete en medio,
                      │  + API + panel web │   lee / modifica / reenvía
                      └─────────┬──────────┘
                                │ :8080 (panel)
                      ┌─────────▼──────────┐       ┌────────────┐
                      │   navegador / tú   │       │el_espameado│
                      │  control del ataque│       │(consumidor)│
                      └────────────────────┘       └────────────┘
```

| Servicio       | Contenedor    | Rol                                                         |
|----------------|---------------|-------------------------------------------------------------|
| `rabbit`       | `amqp`        | Broker RabbitMQ (+ consola de gestión)                      |
| `el_enviador`  | `insaneador`  | Productor: publica mensajes en la cola                      |
| `el_espameado` | `insaneado`   | Consumidor: recibe y **detecta la manipulación**            |
| `el_sniffer`   | `sniffermitm` | Atacante MITM: ARP spoof + **panel de control** en `:8080`  |

---

## 🚀 Cómo levantarlo

Requisitos: **Docker** + plugin **`docker compose`** (Linux o WSL2).
Si no tienes Docker, mira la guía de instalación al final.

```bash
git clone https://github.com/maxxee1/amqp-scapy-injection
cd amqp-scapy-injection/RabbitMQ      # ← OJO: casi todo vive dentro de RabbitMQ/

cp .env.example .env                  # crea tus credenciales (y cámbialas)
docker compose up --build
```

Apagar: `docker compose down`

---

## 🎛️ Panel de control del ataque

Con el stack arriba, abre **http://localhost:8080**

El flujo está pensado para aprender paso a paso:

1. **Apagado** → no se intercepta nada; el consumidor recibe los mensajes intactos.
2. **Prendes el MITM** (modo **Leer**) → empiezas a ver el tráfico en vivo, sin tocarlo.
3. **Cambias a Editar** → defines las reglas de reemplazo y, al activarlas, el
   tráfico se modifica automáticamente (el consumidor pasa a recibir el mensaje alterado).
4. **Estadísticas** (vistos / modificados) + un espacio reservado para el **DPI/defensa** (Parte 2).

> No se edita "en vivo" mensaje a mensaje (eso cortaría la conexión por timeout):
> se **pre-configura la regla** y a partir de ahí actúa sola.

El panel habla con el motor por una **API REST** (`/api/attack`, `/api/mode`,
`/api/rules`, `/api/events`, `/api/status`) — ver [`el_sniffer/README.md`](RabbitMQ/el_sniffer/README.md).

El diseño del front se guió por el template **Horizon UI Tailwind** (solo como
referencia de estilo; no forma parte del proyecto).

---

## 🐰 Consola de RabbitMQ

**http://localhost:15672** — usuario y clave son los de tu `.env`
(`RABBITMQ_USER` / `RABBITMQ_PASS`). Ahí ves las colas, tasas de mensajes,
conexiones, etc.

---

## 🛠️ Cómo funciona el MITM (teoría breve)

En una red *bridge* de Docker el tráfico lo conmuta un **switch virtual**: cada
contenedor solo ve lo suyo, así que un sniffer pasivo **no vería nada**. El truco:

1. **ARP spoofing** — ARP no tiene autenticación, así que el atacante le dice al
   productor "la IP del broker está en MI MAC" y viceversa. Ahora el tráfico pasa por él.
2. **Relay** — reenvía cada paquete a su destino real (si no, se corta la conexión).
3. **Modificación de igual longitud** — reemplaza bytes del payload por la
   **misma cantidad de bytes** (ej. `STATUS=NORMAL` → `STATUS=HACKED`) para no
   desincronizar el framing TCP/AMQP, y recalcula los checksums.

Se usa **relay L2 en user-space** (portable, funciona en WSL2 y Linux, solo
necesita las capacidades `NET_ADMIN`/`NET_RAW`).

---

## 🔐 Principios de seguridad aplicados

- **Secretos fuera del código:** credenciales en `.env` (en `.gitignore`), nunca
  horneadas en las imágenes. Se versiona solo `.env.example`.
- **Dependencias pinneadas** (`pika`, `scapy`, `Flask`) → builds reproducibles.
- **Mínimo privilegio:** productor y consumidor sin root; el atacante usa solo
  `NET_ADMIN`/`NET_RAW` en vez de `privileged`.
- **Arranque ordenado:** `healthcheck` del broker + `depends_on: service_healthy`.
- **Red aislada:** el ataque no sale del bridge privado.

---

## 📦 Puertos y comandos

| Puerto | Servicio |
|---|---|
| `8080`  | Panel de control del MITM |
| `15672` | Consola de RabbitMQ |
| `5672`  | AMQP (broker) |

| Comando | Descripción |
|---|---|
| `docker compose up --build` | Construye y levanta todo |
| `docker compose logs -f el_sniffer` | Ver el ataque en vivo en la terminal |
| `docker compose down` | Detiene y elimina los contenedores |
| `docker compose down -v --rmi all` | Limpia contenedores, volúmenes e imágenes |

---

## 🩺 Troubleshooting

**`cp .env.example .env` dice "No such file or directory".**
Estás en la raíz del repo; el archivo vive en `RabbitMQ/`. Haz `cd RabbitMQ` primero.

**El `build` (apt-get del sniffer) se cuelga con timeouts, pero `curl` sí funciona.**
Es un **desajuste de MTU** típico de WSL2 (o VPNs): el host usa MTU 1280 y Docker
crea sus redes en 1500, con PMTUD roto → las descargas grandes mueren. Fija el MTU
de Docker al del host:

```bash
echo '{ "mtu": 1280 }' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

(Comprueba tu MTU con `ip -o link show eth0 | grep -o 'mtu [0-9]*'`.)

---

## 🗺️ Roadmap (Parte 2)

- [ ] **Escalamiento horizontal** de consumidores (`docker compose up --scale`).
- [ ] **Replay attack**: capturar y reinyectar publicaciones AMQP.
- [ ] **Defensa — DPI / Suricata**: detectar el ARP spoofing, la manipulación y el
      replay con reglas propias, integrado en el mismo panel.

---

<details>
<summary>📥 Instalar Docker en Ubuntu/Debian (si no lo tienes)</summary>

```bash
# Clave GPG + repo oficial
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# Instalar
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Probar
sudo docker run hello-world
```

Documentación oficial 👉 https://docs.docker.com/engine/install/
</details>
