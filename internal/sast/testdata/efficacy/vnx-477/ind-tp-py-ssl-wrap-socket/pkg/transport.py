import socket
import ssl


def connect(host, port):
    sock = socket.create_connection((host, port))
~>    return ssl.wrap_socket(
        sock,
        ssl_version=ssl.PROTOCOL_TLSv1_2,
    )
