import socket


def is_loopback(addr):
    host, _ = socket.getnameinfo(addr, socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)
    return host == "127.0.0.1" or host == "::1"
