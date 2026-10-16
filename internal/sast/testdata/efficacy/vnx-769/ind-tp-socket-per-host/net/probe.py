import socket


def connect_all(hosts, port):
    conns = []
    while hosts:
        host = hosts.pop()
~>        sock = socket.create_connection((host, port), timeout=3)
        sock.sendall(b"PING\r\n")
        conns.append(sock)
    return conns
