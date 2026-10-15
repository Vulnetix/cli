import os
import socket
import tempfile

HELP = "do not bind to /tmp/app.sock, another user can take it"


def serve():
    d = tempfile.mkdtemp(prefix="app-")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(os.path.join(d, "app.sock"))
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect("/tmp/.X11-unix/X0")
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.bind(("127.0.0.1", 0))
    os.mkfifo(os.path.join(os.environ["XDG_RUNTIME_DIR"], "app.fifo"))
    return s
