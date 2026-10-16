import socket
import time


def send_heartbeat(host, port, payload):
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(payload)
    sock.close()
    time.sleep(0.1)
~>    sock.sendall(b"BYE\n")
