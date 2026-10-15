import ssl

import httpx
import requests


def fetch(url, body):
~>    return requests.post(url, json=body, verify = False)


def fetch2(url):
    return requests.get(
        url,
~>        verify=False,
        timeout=5,
    )


client = httpx.Client(
    base_url="https://api.internal",
~>    verify=False,
)


def ctx():
    c = ssl.create_default_context()
~>    c.check_hostname = False
~>    c.verify_mode = ssl.CERT_NONE
    return c
