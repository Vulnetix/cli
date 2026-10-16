import socket


def fetch_banner(host, port):
~>    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((host, port))
    return s.recv(1024).decode()
