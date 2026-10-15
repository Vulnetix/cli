import socket
import ssl
from ssl import wrap_socket as _unused
from ssl import match_hostname


def open_tls(host, port=465):
    raw = socket.create_connection((host, port))
~>    tls = ssl.wrap_socket(raw, ssl_version=ssl.PROTOCOL_TLS_CLIENT)
~>    match_hostname(tls.getpeercert(), host)
    return tls


def check(cert, host):
~>    ssl.match_hostname(cert, host)
