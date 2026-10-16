import os
import socket
import socketserver
import tempfile


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"ok\n")


def control_server():
~>    return socketserver.UnixStreamServer(os.path.join(tempfile.gettempdir(), "syncd.sock"), Handler)


def events_fifo():
~>    os.mkfifo("/tmp/syncd-events")


def raw_socket():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
~>    s.bind("/tmp/syncd-raw.sock")
    s.listen(4)
    return s
