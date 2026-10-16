import socket

def test_connect():
    s = socket.socket()
    s.connect(("10.20.4.17", 9000))
    DB_HOST = "10.20.4.17"
