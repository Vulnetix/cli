import html
import re
import socket
import ssl

from markupsafe import escape


class Client:
    def __init__(self):
        self._ctx = ssl.create_default_context()
        self._server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    def connect(self, host):
        sock = socket.create_connection((host, 443))
        return self._ctx.wrap_socket(sock, server_hostname=host)


def render(name):
    pattern = re.escape(name)
    return f"<b title='{html.escape(name)}'>{escape(pattern)}</b>"
