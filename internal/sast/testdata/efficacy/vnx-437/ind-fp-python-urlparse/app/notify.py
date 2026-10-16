from urllib.parse import urlsplit

import requests

ALLOWED = {"api.partner-data.com"}


def pull(url: str):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5)
