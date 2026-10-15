import socketserver


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"ok\n")


def serve():
~>    server = socketserver.UnixStreamServer(
        "/tmp/control.sock", Handler)
    server.serve_forever()
