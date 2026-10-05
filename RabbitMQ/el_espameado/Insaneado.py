"""
Consumidor AMQP — recibe los mensajes de la cola.

Si el MITM manipuló el tráfico, aquí se nota: el cuerpo recibido NO coincide
con lo que publicó el productor. Marcamos como [ALERTA] los mensajes que
contienen la firma del atacante (STATUS=HACKED o note=pwned).
"""
import os

import pika

HOST = os.environ.get("AMQP_HOST", "rabbit")
PORT = int(os.environ.get("AMQP_PORT", "5672"))
QUEUE = os.environ.get("AMQP_QUEUE", "insane_queue")
USER = os.environ.get("AMQP_USER", "guest")
PASS = os.environ.get("AMQP_PASS", "guest")

# Firmas que deja el atacante MITM (ver el_sniffer/mitm.py)
FIRMAS_ATAQUE = ("STATUS=HACKED", "note=pwned")

print("🐇 Insaneado (consumidor) despertando...", flush=True)


def conectar():
    params = pika.ConnectionParameters(
        host=HOST,
        port=PORT,
        credentials=pika.PlainCredentials(USER, PASS),
        heartbeat=30,
    )
    while True:
        try:
            conn = pika.BlockingConnection(params)
            print("🐇 Conejo encontrado, escuchando 📥", flush=True)
            return conn
        except pika.exceptions.AMQPConnectionError:
            print("🐇 Conejo dormido, reintento en 5s 🫠", flush=True)
            import time
            time.sleep(5)


def callback(ch, method, properties, body):
    texto = body.decode(errors="replace")
    if any(firma in texto for firma in FIRMAS_ATAQUE):
        print(f" [!] ALERTA — mensaje manipulado: {texto} 🚨", flush=True)
    else:
        print(f" [<] Recibido: {texto} 🫶🐇", flush=True)


def main():
    connection = conectar()
    channel = connection.channel()
    channel.queue_declare(queue=QUEUE, durable=True)
    channel.basic_consume(
        queue=QUEUE, on_message_callback=callback, auto_ack=True
    )
    print(" [*] Esperando mensajes. Ctrl+C para salir 🧃", flush=True)
    channel.start_consuming()


if __name__ == "__main__":
    main()
