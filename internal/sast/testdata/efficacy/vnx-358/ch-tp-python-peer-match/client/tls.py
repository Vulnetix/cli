import socket
import ssl


def match_server_host(cert, peer_host):
    for _, name in cert.get("subjectAltName", ()):
~>        if peer_host.endswith(name.lstrip("*")):
            return True
    return False


def check_peer_hostname(sock: ssl.SSLSocket, expected_host: str) -> None:
    cn = dict(x[0] for x in sock.getpeercert()["subject"])["commonName"]
~>    if cn not in expected_host:
        raise ssl.SSLError("hostname mismatch")
