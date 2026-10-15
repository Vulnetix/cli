import Pyro4
import rpyc
from rpyc.utils.server import ThreadedServer
from xmlrpc.server import SimpleXMLRPCServer


class CalcService(rpyc.Service):
    def exposed_add(self, a, b):
        return a + b


@Pyro4.expose
class Warehouse:
    def list(self):
        return []


server = SimpleXMLRPCServer(("localhost", 8000))
server.register_instance(Calculator())
server.register_instance(Calculator(), allow_dotted_names=False)
server.register_function(evaluate_order, "evaluate")
server.register_function(open_ticket)
t = ThreadedServer(CalcService, port=18861, protocol_config={"allow_public_attrs": False, "allow_setattr": False})
@@sample:P[y]ro[4][.]c[o]nf[i]g[.][R]EQ[U]IR[E][_]E[X]PO[S]E@@ = True
