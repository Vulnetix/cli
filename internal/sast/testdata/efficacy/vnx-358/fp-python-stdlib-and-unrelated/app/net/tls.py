import ssl


def make_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    return ctx


def verify_hostname(cert, hostname):
    ssl.match_hostname(cert, hostname)
    return hostname.endswith(".acme.com")


def is_static(path):
    return path.endswith(".css") or "static" in path
