import socket


def test_bind_any():
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    s.close()
