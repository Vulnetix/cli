import requests
from requests.auth import HTTPBasicAuth

def go(url):
~>  return requests.get(url, auth=HTTPBasicAuth("admin", "admin"))
