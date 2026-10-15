import socket


def ping(host):
    sock = socket.create_connection((host, 7))
    sock.sendall(b"ping")
    sock.close()
~>    reply = sock.recv(64)
    return reply
