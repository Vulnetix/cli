import os
import socket


def send_datagram(host, data):
~>    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    sock.sendto(data, (host, 9999))


def peek(path):
~>    fd = os.open(path, os.O_RDONLY)
    return os.read(fd, 16)
