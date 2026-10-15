import requests
from requests.auth import HTTPBasicAuth


def fetch(url, token):
    return requests.get(url, headers={"Authorization": f"Bearer {token}"})


def fetch_basic(url, user, pw):
    return requests.get(url, auth=HTTPBasicAuth(user, pw))
