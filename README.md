# AMQP Scapy Injection — Laboratorio de Ataque y Defensa 🕷️🐇

Laboratorio **reproducible** para aprender a **interceptar, modificar e inyectar**
tráfico **AMQP** (RabbitMQ) usando **Scapy**, mediante un ataque **MITM con ARP
spoofing** real entre contenedores Docker.

> ⚠️ **SOLO USO EDUCATIVO / LABORATORIO AISLADO.**
> Todo corre en una red Docker privada (`red_docker`). No lo uses nunca contra
> redes o equipos ajenos. Es un entorno de práctica para entender cómo funcionan
> estos ataques y cómo defenderse de ellos.

---

## 🧩 Arquitectura

```
                 red_docker (bridge, L2 aislada)
   ┌────────────┐      ARP spoof       ┌────────────┐
   │ el_enviador│◄───────────────────►│   rabbit    │
   │ (productor)│   tráfico AMQP 5672  │ (RabbitMQ)  │
   └─────┬──────┘    (interceptado)    └──────┬──────┘
         │                                    │
         │        ┌───────────────────┐       │
         └───────►│    el_sniffer     │◄──────┘
                  │  MITM (Scapy)     │   se mete en medio,
                  │  ARP spoof +      │   modifica el payload
                  │  relay / nfqueue  │   y reenvía
                  └───────────────────┘
                              │
                        ┌─────▼──────┐
                        │el_espameado│  recibe el mensaje
                        │(consumidor)│  YA MANIPULADO
                        └────────────┘
```

| Servicio       | Contenedor   | Rol                                                        |
|----------------|--------------|------------------------------------------------------------|
| `rabbit`       | `amqp`       | Broker RabbitMQ (UI en http://localhost:15672)             |
| `el_enviador`  | `insaneador` | Productor: publica mensajes en la cola                     |
| `el_espameado` | `insaneado`  | Consumidor: recibe y **detecta la manipulación**           |
| `el_sniffer`   | `sniffermitm`| Atacante MITM: ARP spoof + intercepta/modifica frames AMQP |

---

## 🚀 Cómo levantarlo

Requisitos: **Docker** + **plugin `docker compose`** (en Linux o WSL2).
Si no tienes Docker, al final de este README está la guía de instalación en Ubuntu.

```bash
git clone https://github.com/maxxee1/amqp-scapy-injection
cd amqp-scapy-injection/RabbitMQ

# 1) Crea tu archivo de secretos a partir de la plantilla y cambia la clave
cp .env.example .env
#   (edita .env y pon una contraseña distinta)

# 2) Construye y levanta todo
docker compose up --build
```

Para apagar:

```bash
docker compose down
```

---

## 👀 Qué vas a ver (el ataque en acción)

El productor envía mensajes con campos de **ancho fijo**:

```
el_enviador  | [>] Enviado:  msg#000007|STATUS=NORMAL|amount=00000100|note=legit
```

El MITM los intercepta y reemplaza marcadores **conservando la longitud**
(para no romper el framing TCP/AMQP):

```
el_sniffer   | 👀 ORIGINAL : b'...STATUS=NORMAL...note=legit'
el_sniffer   | 💥 MODIFICADO: b'...STATUS=HACKED...note=pwned'
```

Y el consumidor recibe el mensaje **ya alterado** y lo marca como ataque:

```
el_espameado | [!] ALERTA — mensaje manipulado: msg#000007|STATUS=HACKED|amount=00000100|note=pwned 🚨
```

Eso demuestra el impacto: un atacante en la ruta puede cambiar el contenido de
los mensajes sin que el broker ni las aplicaciones lo noten por sí solos.

---

## 🛠️ Cómo funciona el MITM (`el_sniffer/mitm.py`)

1. **Resuelve** las IPs/MACs del productor y del broker.
2. **Envenena las cachés ARP** de ambos (ARP spoofing): cada víctima cree que la
   MAC de la otra es la del atacante, así el tráfico pasa por en medio.
3. **Intercepta** los frames AMQP (puerto 5672) y **reemplaza** los marcadores.
4. **Reenvía** el paquete modificado a su destino real.

### Dos modos (`MITM_MODE` en `.env`)

| Modo      | Cómo intercepta                              | Requisitos                                   |
|-----------|----------------------------------------------|----------------------------------------------|
| `relay`   | Reenvío L2 en user-space con Scapy (default) | Solo caps `NET_ADMIN`/`NET_RAW`. **Portable** (WSL2 incluido) |
| `nfqueue` | `iptables -j NFQUEUE` + NetfilterQueue       | Kernel host con `nfnetlink_queue` (Kali/VM real) |

> En **WSL2** el módulo `nfnetlink_queue` no siempre está disponible, por eso el
> modo por defecto es `relay`. En una VM Linux/Kali real puedes usar `nfqueue`.

---

## 🔐 Principios de seguridad aplicados

- **Secretos fuera del código:** credenciales en `.env` (en `.gitignore`), nunca
  hardcodeadas ni horneadas en las imágenes. Se versiona solo `.env.example`.
- **Dependencias pinneadas** (`pika==1.3.2`, `scapy==2.5.0`, …) → builds reproducibles
  y menos riesgo de cadena de suministro.
- **Mínimo privilegio:** productor y consumidor corren como usuario sin root; el
  atacante usa solo `NET_ADMIN`/`NET_RAW` en vez de `privileged: true`.
- **Arranque ordenado:** `healthcheck` del broker + `depends_on: service_healthy`.
- **Red aislada:** todo ocurre en un bridge privado; el ataque no sale de ahí.

---

## 🗺️ Roadmap (Parte 2)

- [ ] **Escalamiento horizontal** de consumidores (`docker compose up --scale`).
- [ ] **Replay attack**: capturar y reinyectar publicaciones AMQP (mensajes duplicados).
- [ ] **Defensa — DPI / Suricata**: IDS/IPS que detecte el ARP spoofing, la
      manipulación de payload y el replay, con reglas propias.

---

## 📦 Comandos útiles

| Comando | Descripción |
|---|---|
| `docker compose up --build` | Construye y levanta todo |
| `docker compose logs -f el_sniffer` | Ver el ataque en vivo |
| `docker compose down` | Detiene y elimina contenedores |
| `docker compose down -v --rmi all` | Limpia contenedores, volúmenes e imágenes |
| `docker ps` | Contenedores en ejecución |

---

<details>
<summary>📥 Instalar Docker en Ubuntu (si no lo tienes)</summary>

```bash
# Verificar
docker --version

# Eliminar versiones previas (opcional)
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done

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
