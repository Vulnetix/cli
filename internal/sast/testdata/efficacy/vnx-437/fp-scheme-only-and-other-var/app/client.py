import requests

BASE = "https://api.partner-data.com/v1/"


def get(path, url):
    if not url.startswith("https://"):
        raise ValueError("https only")
    if "partner-data.com" in url:
        return requests.get(BASE + path, timeout=5)
    return requests.get(url, timeout=5)


def label(name):
    if "acme.example.com" in name:
        return name.upper()
