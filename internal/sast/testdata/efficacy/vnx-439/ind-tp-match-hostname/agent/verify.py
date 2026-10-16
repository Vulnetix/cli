import ssl


def check_peer(sock, expected_host):
    cert = sock.getpeercert()
~>    ssl.match_hostname(cert, expected_host)
    return cert
