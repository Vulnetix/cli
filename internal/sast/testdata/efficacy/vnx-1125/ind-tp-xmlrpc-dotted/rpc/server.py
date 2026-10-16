from xmlrpc.server import SimpleXMLRPCServer

class Inventory:
    def count(self):
        return 3

server = SimpleXMLRPCServer(("0.0.0.0", 8000))
~>server.register_instance(Inventory(), allow_dotted_names=True)
server.serve_forever()
