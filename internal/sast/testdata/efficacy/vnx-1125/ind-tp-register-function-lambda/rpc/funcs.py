import os
import subprocess
from xmlrpc.server import SimpleXMLRPCServer

server = SimpleXMLRPCServer(("127.0.0.1", 9000))
~>server.register_function(os.system, "run")
~>server.register_function(lambda cmd: subprocess.check_output(cmd, shell=True), "sh")
