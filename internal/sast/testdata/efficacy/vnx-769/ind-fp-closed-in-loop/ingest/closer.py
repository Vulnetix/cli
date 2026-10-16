import socket


def ping(hosts):
    for host in hosts:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, 80))
        finally:
            s.close()
    for p in hosts:
        fh = open(p)
        data = fh.read()
        fh.close()
