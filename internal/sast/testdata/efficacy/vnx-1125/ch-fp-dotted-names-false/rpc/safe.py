from xmlrpc.server import SimpleXMLRPCServer

server = SimpleXMLRPCServer(("127.0.0.1", 8000))
server.register_instance(Api(), allow_dotted_names=False)
server.register_instance(
    Api(),
    allow_dotted_names=False,
)
