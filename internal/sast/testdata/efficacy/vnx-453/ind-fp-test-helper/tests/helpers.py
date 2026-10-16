import requests


def make_client(base_url, verify=False, debug=True):
    s = requests.Session()
    s.verify = verify
    return s
