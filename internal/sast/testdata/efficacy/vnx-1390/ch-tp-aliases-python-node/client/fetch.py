import requests
from requests.auth import HTTPDigestAuth as DigestCreds


def fetch_status(url, user, password):
~>    auth = DigestCreds(user, password)
    return requests.get(url, auth=auth, timeout=10)


def fetch_camera(url, user, password):
~>    return requests.get(url, auth=requests.auth.HTTPDigestAuth(user, password), timeout=5)
