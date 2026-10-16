import os
import socket
import tempfile

LOG = "/tmp/ctl.log"


def send(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/tmp/syncd.sock")
    s.sendall(cmd.encode())


def private_fifo():
    d = tempfile.mkdtemp()
    os.mkfifo(os.path.join(d, "events"))


def tcp():
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.bind(("0.0.0.0", 9000))
    # s.bind("/tmp/old.sock") was the previous layout
