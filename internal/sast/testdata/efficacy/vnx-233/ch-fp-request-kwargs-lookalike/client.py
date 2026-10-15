import requests


def fetch(url, timeout=10, **request_kwargs):
    request_options = {"timeout": timeout, **request_kwargs}
    return requests.get(url, **request_options)
