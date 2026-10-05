FROM python:3.11-slim

# Solo herramientas de red livianas para inspección (tcpdump, ip).
# Ya NO compilamos netfilterqueue -> build mucho más rápido.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine.py app.py ./
COPY static ./static

EXPOSE 8080

# Necesita root + cap NET_ADMIN/NET_RAW (ver docker-compose.yml).
CMD ["python", "-u", "app.py"]
