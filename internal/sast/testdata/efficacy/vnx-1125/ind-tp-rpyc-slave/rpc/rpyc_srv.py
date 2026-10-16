from rpyc.utils.server import ThreadedServer
from rpyc.core.service import SlaveService

if __name__ == "__main__":
~>    t = ThreadedServer(SlaveService, hostname="0.0.0.0", port=18812)
    t.start()
