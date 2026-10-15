import socket
import ssl
from ssl import SSLContext, PROTOCOL_TLS


def connect(host):
~>    ctx = ssl.SSLContext()
    sock = socket.create_connection((host, 443))
    return ctx.wrap_socket(sock, server_hostname=host)


def legacy(host):
~>    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
~>    other = SSLContext(PROTOCOL_TLS)
~>    third = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    return ctx, other, third
