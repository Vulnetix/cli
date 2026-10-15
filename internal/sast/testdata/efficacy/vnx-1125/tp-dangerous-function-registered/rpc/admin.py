import os
import subprocess
from xmlrpc.server import SimpleXMLRPCServer

server = SimpleXMLRPCServer(("localhost", 9000), allow_none=True)
server.register_function(list_jobs)
~>server.register_function(os.system, "run")
~>server.register_function( eval )
~>server.register_function(subprocess.check_output, "sh")
server.serve_forever()
