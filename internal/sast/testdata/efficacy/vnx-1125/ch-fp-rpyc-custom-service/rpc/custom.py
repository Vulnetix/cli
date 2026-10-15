import rpyc
from rpyc.utils.server import ThreadedServer


class CalcService(rpyc.Service):
    def exposed_add(self, a, b):
        return a + b


t = ThreadedServer(CalcService, port=18861, protocol_config={"allow_public_attrs": True})
t = ThreadedServer(service=CalcService, port=18861)
t.start()
