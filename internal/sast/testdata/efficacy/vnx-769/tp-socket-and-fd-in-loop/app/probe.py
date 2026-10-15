import os
import socket


def probe(hosts):
    alive = []
    for host in hosts:
~>        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex((host, 22)) == 0:
            alive.append(host)
    return alive


def checksum(paths):
    total = 0
    while paths:
        p = paths.pop()
~>        fd = os.open(p, os.O_RDONLY)
        total += len(os.read(fd, 4096))
    return total


def reconnect(addr):
    while True:
~>        conn = socket.create_connection(addr, timeout=5)
        conn.sendall(b"ping")
