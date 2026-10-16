import requests
from requests.auth import HTTPDigestAuth

def fetch(url, user, pw):
~>  return requests.get(url, auth=HTTPDigestAuth(user, pw), timeout=10)
