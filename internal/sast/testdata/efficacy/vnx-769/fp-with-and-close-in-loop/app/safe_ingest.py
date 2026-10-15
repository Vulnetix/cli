import json
import os
import socket


def load_all(paths):
    records = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            records.append(json.load(fh))
    return records


def probe(hosts):
    alive = []
    for host in hosts:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if s.connect_ex((host, 22)) == 0:
                alive.append(host)
        finally:
            s.close()
    return alive


def checksum(paths):
    total = 0
    for p in paths:
        fd = os.open(p, os.O_RDONLY)
        total += len(os.read(fd, 4096))
        os.close(fd)
    return total
