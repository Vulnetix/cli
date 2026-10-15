import socket


def fetch_banner(host, port):
~>    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    banner = s.recv(1024)
    return banner.decode()


def notify(addr, payload):
~>    conn = socket.create_connection(addr, timeout=3)
    conn.sendall(payload)
