from urllib.parse import urlparse

ALLOWED = {"https://app.example.com"}


def allowed(origin):
    if origin in ALLOWED:
        return True
    host = urlparse(origin).hostname or ""
    return host == "example.com" or host.endswith(".example.com")


def check(origin):
    return re.fullmatch(r"https://([a-z]+\.)?example\.com", origin) is not None
