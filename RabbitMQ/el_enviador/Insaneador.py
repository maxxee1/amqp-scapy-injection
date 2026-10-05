"""
Productor AMQP — publica mensajes en la cola.

Cada mensaje lleva campos de ANCHO FIJO a propósito. Eso permite que el
atacante MITM los modifique conservando la longitud (sin romper el framing
TCP/AMQP). Así se ve el ataque de forma limpia:

    msg#000042|STATUS=NORMAL|amount=00000100|note=legit

El MITM puede cambiar, por ejemplo, NORMAL -> HACKED o el monto, manteniendo
la misma cantidad de bytes.
"""
import os
import time

import pika

HOST = os.environ.get("AMQP_HOST", "rabbit")
PORT = int(os.environ.get("AMQP_PORT", "5672"))
QUEUE = os.environ.get("AMQP_QUEUE", "insane_queue")
USER = os.environ.get("AMQP_USER", "guest")
PASS = os.environ.get("AMQP_PASS", "guest")

print("🐇 Insaneador (productor) despertando...", flush=True)


def conectar():
    """Reintenta hasta que el broker esté disponible."""
    params = pika.ConnectionParameters(
        host=HOST,
        port=PORT,
        credentials=pika.PlainCredentials(USER, PASS),
        heartbeat=30,
    )
    while True:
        try:
            conn = pika.BlockingConnection(params)
            print("🐇 Conejo encontrado, enviando 💌", flush=True)
            return conn
        except pika.exceptions.AMQPConnectionError:
            print("🐇 Conejo dormido, reintento en 5s 🫠", flush=True)
            time.sleep(5)


def main():
    connection = conectar()
    channel = connection.channel()
    # Cola durable para que sobreviva reinicios del broker
    channel.queue_declare(queue=QUEUE, durable=True)

    contador = 1
    while True:
        # Campos de ancho fijo: STATUS=6 chars, amount=8 digitos, note=5 chars
        mensaje = (
            f"msg#{contador:06d}|STATUS=NORMAL|amount=00000100|note=legit"
        )
        try:
            channel.basic_publish(
                exchange="",
                routing_key=QUEUE,
                body=mensaje,
                properties=pika.BasicProperties(delivery_mode=2),  # persistente
            )
            print(f" [>] Enviado:  {mensaje}", flush=True)
        except (pika.exceptions.AMQPConnectionError,
                pika.exceptions.StreamLostError):
            print("🐇 Conexión perdida, reconectando...", flush=True)
            connection = conectar()
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE, durable=True)
            continue

        contador += 1
        time.sleep(2)


if __name__ == "__main__":
    main()
