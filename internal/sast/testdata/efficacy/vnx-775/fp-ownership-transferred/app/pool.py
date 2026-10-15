import socket
import ssl


def make_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s


class Client:
    def __init__(self, host):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw = socket.create_connection((host, 443))
        self.tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)

    def register(self, path):
        fh = open(path, "a")
        self.handles.append(fh)


def read_text(path):
    return open(path).read()


LOG = open("/var/log/app.log", "a")
