import socket
import ssl


def make_socket(host, port):
    s = socket.socket()
    s.connect((host, port))
    return s


def tls(host, ctx):
    raw = socket.create_connection((host, 443))
    return ctx.wrap_socket(raw, server_hostname=host)


class Client:
    def __init__(self, path):
        self.fh = open(path)

    def add(self, p):
        f = open(p)
        self.files.append(f)


def whole(p):
    return open(p).read()


def gen(p):
    fh = open(p)
    yield from fh
