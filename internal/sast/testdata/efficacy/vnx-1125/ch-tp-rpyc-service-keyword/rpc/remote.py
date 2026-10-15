import rpyc
from rpyc.utils.server import ThreadPoolServer

~>srv = ThreadPoolServer(service=rpyc.ClassicService, hostname="0.0.0.0", port=18812)
srv.start()
