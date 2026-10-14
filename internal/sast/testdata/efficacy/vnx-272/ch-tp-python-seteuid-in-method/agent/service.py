import os
import socket


class Agent:
    def __init__(self, port):
        self.port = port

    def bind(self):
~>        os.setegid(0)
~>        os.seteuid(0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", self.port))
        sock.listen(16)
        return sock
