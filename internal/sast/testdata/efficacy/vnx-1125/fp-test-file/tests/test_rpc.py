from rpyc.utils.server import ThreadedServer
from rpyc.core.service import SlaveService


def test_classic_roundtrip():
    srv = ThreadedServer(SlaveService, port=0)
    srv.close()
