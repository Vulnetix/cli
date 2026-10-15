import html
import re
import socket
import ssl


def connect(host):
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, 443))
    return ctx.wrap_socket(sock, server_hostname=host)


def explicit(host):
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    server = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
    return client, server


def render(name):
    return "<b>" + html.escape(name) + "</b>" + re.escape(name)
