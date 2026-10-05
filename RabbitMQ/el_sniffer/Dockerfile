FROM python:3.11-slim

# Herramientas de red + toolchain para compilar netfilterqueue.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libnetfilter-queue-dev \
        iptables \
        iproute2 \
        tcpdump \
        libpcap-dev \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mitm.py .

# Necesita root + cap NET_ADMIN/NET_RAW (ver docker-compose.yml).
CMD ["python", "-u", "mitm.py"]
