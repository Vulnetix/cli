from xmlrpc.server import SimpleXMLRPCServer


class Api:
    def ping(self):
        return "pong"


server = SimpleXMLRPCServer(("0.0.0.0", 8000))
~>server.register_instance(
    Api(),
    allow_dotted_names=True,
)
server.serve_forever()
