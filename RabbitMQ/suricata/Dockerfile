FROM jasonish/suricata:7.0

# python3 para el tailer que reenvía eve.json al panel.
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

COPY local.rules /rules/local.rules
COPY tail_eve.py /tail_eve.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Comparte el netns del broker (ver docker-compose.yml); necesita NET_RAW/NET_ADMIN.
ENTRYPOINT ["/entrypoint.sh"]
