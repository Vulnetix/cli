import socket


def is_googlebot(ip):
    host = socket.gethostbyaddr(ip)[0]
    if not host.endswith((".googlebot.com", ".google.com")):
        return False
    return ip in socket.gethostbyname_ex(host)[2]
