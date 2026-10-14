import socket
import ssl


def connect(host):
~>    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return ctx.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)


def legacy(sock):
~>    return ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3)


def legacy11(sock):
    return ssl.wrap_socket(
        sock,
~>        ssl_version=ssl.PROTOCOL_TLSv1_1,
    )
