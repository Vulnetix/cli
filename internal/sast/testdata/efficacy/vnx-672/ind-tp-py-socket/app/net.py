import socket


def ping(host):
    s = socket.create_connection((host, 80))
    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
    s.close()
~>    data = s.recv(1024)
    return data
