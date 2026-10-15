import socket


def send(host, payload):
    s = socket.create_connection((host, 80))
~>    s.sendall(b"POST /api HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" + payload)
    return s.recv(4096)
