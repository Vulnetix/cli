from urllib.parse import urlparse

import requests

ALLOWED = {"api.partner-data.com"}


def fetch(url):
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text


def fetch_prefix(url):
    if not url.startswith("https://api.partner-data.com/"):
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).text
