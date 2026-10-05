FROM jasonish/suricata:7.0

# Solo corre Suricata con nuestras reglas. El reenvío de eve.json al panel
# lo hace el contenedor del DPI (que ya tiene Python) vía un volumen compartido.
COPY local.rules /rules/local.rules
COPY entrypoint.sh /entrypoint.sh

# Comparte el netns del broker (ver docker-compose.yml); necesita NET_RAW/NET_ADMIN.
ENTRYPOINT ["sh", "/entrypoint.sh"]
