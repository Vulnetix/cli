import socket

from sqlalchemy import create_engine

~>engine = create_engine("postgresql://report:secret@192.168.40.12:5432/reports")


def send(payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
~>    sock.connect(("192.168.40.20", 9000))
    sock.sendall(payload)
    sock.close()


SETTINGS = {
~>    "broker_url": "amqp://guest@192.168.40.30//",
~>    "host": "192.168.40.31",
}
