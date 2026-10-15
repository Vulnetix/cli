import socket


def fetch(host):
    s = socket.create_connection((host, 80))
    try:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        return s.recv(1024)
    finally:
        s.close()


def size(path):
    fh = open(path, "rb")
    try:
        return len(fh.read())
    finally:
        fh.close()
