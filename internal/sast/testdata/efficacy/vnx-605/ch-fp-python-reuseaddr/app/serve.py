import socket

# SO_REUSEPORT is deliberately not used here: one owner per port.
def bind(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    has_reuseport = hasattr(socket, "SO_REUSEPORT")
    s.bind(("127.0.0.1", port))
    return s, has_reuseport


def bind_single(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 0)
    return s
