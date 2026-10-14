import os
import socketserver


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"ok\n")


def start(sock_path):
~>    previous = os.umask(0o000)
    server = socketserver.UnixStreamServer(sock_path, Handler)
    server.serve_forever()
    return previous
