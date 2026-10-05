FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dpi.py .

# Comparte el netns del broker (ver docker-compose.yml); necesita NET_RAW.
CMD ["python", "-u", "dpi.py"]
