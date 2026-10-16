from xmlrpc.server import SimpleXMLRPCServer
import os

def test_it():
    s = SimpleXMLRPCServer(("127.0.0.1", 0))
    s.register_instance(object(), allow_dotted_names=True)
    s.register_function(os.system, "run")
