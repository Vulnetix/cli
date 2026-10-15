import os
import socket


def test_roundtrip():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("/tmp/test-agent.sock")
    os.mkfifo("/tmp/test-agent.fifo")
