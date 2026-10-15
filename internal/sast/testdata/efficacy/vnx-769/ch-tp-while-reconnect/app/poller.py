import socket
import time


def poll(host, port):
    while True:
~>        conn = socket.create_connection((host, port), timeout=5)
        conn.sendall(b"PING\n")
        reply = conn.recv(64)
        if reply != b"PONG\n":
            print("bad reply", reply)
        time.sleep(1)
