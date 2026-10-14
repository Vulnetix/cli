import requests


def fetch(url):
~>    return requests.get(url, verify=False, timeout=10)


def push(url, payload):
    resp = requests.post(
        url,
        json=payload,
~>        verify=False,
    )
    resp.raise_for_status()
    return resp
