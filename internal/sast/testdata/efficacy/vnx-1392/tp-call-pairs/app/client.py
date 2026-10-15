import requests
from requests.auth import HTTPBasicAuth


def status(url):
~>    return requests.get(url, auth=HTTPBasicAuth("admin", "admin"))


def legacy(url):
~>    return requests.get(url, auth=("admin", "password"))
