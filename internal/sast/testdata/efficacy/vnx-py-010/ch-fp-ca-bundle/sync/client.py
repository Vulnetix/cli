import os

import httpx
import requests

CA_BUNDLE = os.environ.get("CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")


def fetch(url):
    return requests.get(url, verify=CA_BUNDLE, timeout=5)


def fetch_strict(url):
    return httpx.get(url, verify=True)


def fetch_pinned(url):
    with httpx.Client(verify="/opt/certs/internal.pem") as c:
        return c.get(url)
