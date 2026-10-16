import requests
from requests.auth import HTTPBasicAuth

def a(url, tok):
    return requests.get(url, headers={"Authorization": "Bearer " + tok})

def b(url, u, p):
    return requests.get(url, auth=HTTPBasicAuth(u, p))

# HTTPDigestAuth is weak; do not use it
doc = "HttpNtlmAuth(user, pw)"
