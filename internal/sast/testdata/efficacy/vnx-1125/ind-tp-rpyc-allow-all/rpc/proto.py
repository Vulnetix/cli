from rpyc.utils.server import ThreadedServer
import rpyc

class Calc(rpyc.Service):
    def exposed_add(self, a, b):
        return a + b

t = ThreadedServer(Calc, port=18861, protocol_config={
    "allow_public_attrs": True,
~>    "allow_all_attrs": True,
})
