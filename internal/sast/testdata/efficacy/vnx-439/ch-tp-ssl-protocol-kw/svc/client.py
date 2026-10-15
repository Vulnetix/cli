import socket
import ssl
from ssl import SSLContext, PROTOCOL_SSLv23


def open_conn(host, port=443):
~>    ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    ctx.load_default_certs()
    raw = socket.create_connection((host, port))
    return ctx.wrap_socket(raw, server_hostname=host)


def legacy_ctx():
~>    return SSLContext(PROTOCOL_SSLv23)
