from urllib.parse import urlsplit

import requests


def pull(feed_url):
    netloc = urlsplit(feed_url).netloc
    if netloc.endswith(".feeds.acme.example.com"):
        return requests.get(feed_url, timeout=10)
    host = urlsplit(feed_url).hostname
    if host == "feeds.acme.example.com":
        return requests.get(feed_url, timeout=10)
    return None
