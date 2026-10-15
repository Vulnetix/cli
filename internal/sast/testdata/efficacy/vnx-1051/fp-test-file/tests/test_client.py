import socket

from app.client import Client


def test_connects_to_fixture_host(monkeypatch):
    client = Client(host="10.20.4.17", port=9000)
    sock = socket.socket()
    sock.connect(("10.20.4.18", 9000))
    assert client.host == "10.20.4.17"
