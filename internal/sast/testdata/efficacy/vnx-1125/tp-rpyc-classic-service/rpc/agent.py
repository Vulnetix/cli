import rpyc
from rpyc.core.service import SlaveService
from rpyc.utils.server import ThreadedServer, ForkingServer

~>t = ThreadedServer(SlaveService, hostname="0.0.0.0", port=18812)
~>f = ForkingServer(rpyc.ClassicService, port=18813)
~>conf = {"allow_all_attrs": True, "allow_pickle": False}
~>s2 = ThreadedServer(MyService, port=18814, protocol_config={"allow_setattr": True})
t.start()
