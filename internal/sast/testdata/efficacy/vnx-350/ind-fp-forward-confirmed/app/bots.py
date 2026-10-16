import socket


def is_googlebot(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return False
    if not host.endswith((".googlebot.com", ".google.com")):
        return False
    return ip in socket.gethostbyname_ex(host)[2]
