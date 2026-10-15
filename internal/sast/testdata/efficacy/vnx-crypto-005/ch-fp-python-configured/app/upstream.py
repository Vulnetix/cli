import certifi
import requests


def make(insecure: bool):
    s = requests.Session()
    s.verify = certifi.where()
    return s


def fetch(url, opts):
    return requests.get(url, verify=not opts.insecure)
