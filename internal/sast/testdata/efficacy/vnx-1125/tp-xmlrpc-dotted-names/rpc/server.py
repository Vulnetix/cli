from xmlrpc.server import SimpleXMLRPCServer

from .inventory import Inventory

server = SimpleXMLRPCServer(("0.0.0.0", 8000))
~>server.register_instance(Inventory(), allow_dotted_names=True)
~>server.register_instance(Inventory(), True)
server.serve_forever()
