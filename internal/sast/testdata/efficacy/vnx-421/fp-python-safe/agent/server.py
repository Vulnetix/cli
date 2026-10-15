import os
import socket
import tempfile

RUNTIME = os.environ.get("XDG_RUNTIME_DIR", "/run/user/1000")
LOG_FILE = "/tmp/agent.log"


def serve():
    d = tempfile.mkdtemp()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(os.path.join(d, "agent.sock"))
    s.bind(os.path.join(RUNTIME, "agent.sock"))
    os.mkfifo(os.path.join(d, "events"))


def tcp():
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.bind(("0.0.0.0", 9000))


def client():
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect("/tmp/agent.sock")
    with open(LOG_FILE, "a") as fh:
        fh.write("connected")
