import os
import requests


def fetch(url):
~>    os.environ["CURL_CA_BUNDLE"] = ""
~>    os.environ["REQUESTS_CA_BUNDLE"] = ''
~>    os.environ["PYTHONHTTPSVERIFY"] = "0"
    return requests.get(url)
