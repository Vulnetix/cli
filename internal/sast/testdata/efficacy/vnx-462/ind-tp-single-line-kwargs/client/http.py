import requests


def fetch(url):
~>    options = {"verify": True, "timeout": 10, "verify": False}
    return requests.get(url, **options)
