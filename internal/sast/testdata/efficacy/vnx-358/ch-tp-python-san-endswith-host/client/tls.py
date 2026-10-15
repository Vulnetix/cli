import socket
import ssl


def verify_peer_host(sslsock, hostname):
    cert = sslsock.getpeercert()
    for kind, value in cert.get("subjectAltName", ()):
~>        if kind == "DNS" and value.endswith(hostname):
            return True
    return False


def connect(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    sock = ctx.wrap_socket(socket.create_connection((host, port)))
    if not verify_peer_host(sock, host):
        raise ssl.SSLError("host mismatch")
    return sock
