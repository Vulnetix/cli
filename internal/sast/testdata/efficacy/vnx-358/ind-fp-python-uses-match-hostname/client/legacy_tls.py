import ssl


def verify_hostname(cert, hostname):
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    ssl.match_hostname(cert, hostname)
    return True
