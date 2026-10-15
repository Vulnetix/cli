import contextlib
import os
import socket


def fetch_banner(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        return s.recv(1024)


def load(path):
    fh = open(path)
    try:
        return fh.read()
    finally:
        fh.close()


def peek(path):
    fd = os.open(path, os.O_RDONLY)
    data = os.read(fd, 16)
    os.close(fd)
    return data


def closing_style(addr):
    conn = socket.create_connection(addr)
    with contextlib.closing(conn):
        conn.sendall(b"x")
