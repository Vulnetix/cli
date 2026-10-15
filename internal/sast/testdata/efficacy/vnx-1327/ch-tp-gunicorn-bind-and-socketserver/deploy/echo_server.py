import socketserver


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(data)


if __name__ == "__main__":
~>    with socketserver.TCPServer(("", 9000), EchoHandler) as server:
        server.serve_forever()
