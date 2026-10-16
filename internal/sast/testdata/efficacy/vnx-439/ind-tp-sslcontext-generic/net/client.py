import socket
import ssl


def connect(host: str, port: int = 443):
~>    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
    raw = socket.create_connection((host, port))
    return ctx.wrap_socket(raw, server_hostname=host)


def legacy_context():
~>    return ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)


def bare_context():
~>    return ssl.SSLContext()
