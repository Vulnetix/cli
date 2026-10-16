import socket
import ssl


def verify_hostname(sock, hostname):
    cert = sock.getpeercert()
    for kind, value in cert.get("subjectAltName", ()):
~>        if kind == "DNS" and hostname.endswith(value.lstrip("*")):
            return True
    return False


def connect(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    raw = socket.create_connection((host, port))
    sock = ctx.wrap_socket(raw, server_hostname=host)
    if not verify_hostname(sock, host):
        sock.close()
        raise ssl.SSLError("hostname mismatch")
    return sock
