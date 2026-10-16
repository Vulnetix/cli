import socket
import ssl


def connect(host: str, port: int = 443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()
    raw = socket.create_connection((host, port))
    return ctx.wrap_socket(raw, server_hostname=host)


def server_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def default():
    return ssl.create_default_context()
