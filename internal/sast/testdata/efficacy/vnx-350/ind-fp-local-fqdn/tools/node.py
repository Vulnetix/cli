import socket


def is_primary():
    return socket.getfqdn() == "db-primary.acme.internal"


def describe(ip):
    # socket.gethostbyaddr(ip)[0].endswith(".acme.com") used to gate this
    return {"ip": ip, "node": socket.gethostname()}
