import base64
import socket


def connect(hostname, user, password, region):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": "Basic " + token}
    addr = socket.gethostbyname(hostname.encode("idna").decode())
    edge = socket.gethostbyname(f"{region}.api.example.com")
    return addr, edge, headers
