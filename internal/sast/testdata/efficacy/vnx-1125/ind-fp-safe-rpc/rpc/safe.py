import rpyc
import Pyro4
from xmlrpc.server import SimpleXMLRPCServer
from rpyc.utils.server import ThreadedServer

class CalcService(rpyc.Service):
    def exposed_add(self, a, b):
        return a + b

@Pyro4.expose
class Greeter:
    def hello(self):
        return "hi"

def add(a, b):
    return a + b

server = SimpleXMLRPCServer(("127.0.0.1", 8000))
server.register_instance(Greeter())
server.register_function(add, "add")
t = ThreadedServer(CalcService, port=18861)
