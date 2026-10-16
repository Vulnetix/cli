import socket
from ssl import wrap_socket, CERT_REQUIRED


def open_channel(host, port, ca_file):
    raw = socket.create_connection((host, port), timeout=15)
~>    return wrap_socket(raw, ca_certs=ca_file, cert_reqs=CERT_REQUIRED)
