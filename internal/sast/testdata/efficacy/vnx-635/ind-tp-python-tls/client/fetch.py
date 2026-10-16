import requests


def fetch(url):
~>    # FIXME: disable ssl verification only for staging, this is insecure
    return requests.get(url, verify=False)
