import requests

from app.settings import VERIFY_TLS, CA_BUNDLE


def fetch(url):
    return requests.get(url, verify=CA_BUNDLE)


def fetch2(url):
    return requests.get(url, verify=VERIFY_TLS, timeout=3)
