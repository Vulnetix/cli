import socket
from ssl import PROTOCOL_SSLv23, PROTOCOL_TLSv1, wrap_socket


def connect(host):
    sock = socket.create_connection((host, 443))
~>    return wrap_socket(sock, ssl_version=PROTOCOL_TLSv1)
