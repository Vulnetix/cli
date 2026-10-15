import socket


def test_connect():
    s = socket.socket()
    s.connect(("127.0.0.1", 1))
