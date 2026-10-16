import contextlib
import os
import socket


def a(path):
    with open(path) as fh:
        return fh.read()


def b(path):
    fh = open(path)
    try:
        return fh.read()
    finally:
        fh.close()


def c(host):
    s = socket.create_connection((host, 80))
    with contextlib.closing(s):
        return s.recv(10)


def d(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        return os.read(fd, 10)
    finally:
        os.close(fd)
