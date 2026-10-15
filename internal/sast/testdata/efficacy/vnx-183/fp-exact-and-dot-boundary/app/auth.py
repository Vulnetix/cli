from urllib.parse import urlparse

ALLOWED_HOSTS = ["acme.com", "www.acme.com"]
ALLOWED_REDIRECT_HOSTS = {"acme.com", "shop.acme.com"}


def is_trusted_host(hostname):
    return hostname == "acme.com" or hostname.endswith(".acme.com")


def safe_next(url):
    host = urlparse(url).hostname
    return host in ALLOWED_REDIRECT_HOSTS


def prefix_ok(url):
    return url.startswith("https://acme.com/")
