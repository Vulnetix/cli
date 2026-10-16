import ssl


def check_server_hostname(ssl_sock, host):
    cert = ssl_sock.getpeercert()
    subject = dict(item[0] for item in cert["subject"])
    cn = subject.get("commonName", "")
~>    return cn in host
