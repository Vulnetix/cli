import ssl


def verify_hostname(cert, hostname):
    for kind, value in cert.get("subjectAltName", ()):
~>        if hostname.endswith(value.lstrip("*")):
            return True
    return False


def match_host(cert, host):
    cn = dict(x[0] for x in cert["subject"])["commonName"]
~>    return cn in host


def check_server_hostname(sock, expected):
    peer = sock.getpeercert()
    names = [v for k, v in peer.get("subjectAltName", ())]
~>    return any(expected.startswith(n) for n in names)
