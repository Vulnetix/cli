import socket
from ssl import wrap_socket, CERT_NONE

try:
    from ssl import match_hostname
except ImportError:
    match_hostname = None


def connect(host, port):
    raw = socket.create_connection((host, port))
~>    tls = wrap_socket(raw, cert_reqs=CERT_NONE)
    if match_hostname is not None:
~>        match_hostname(tls.getpeercert(), host)
    return tls
