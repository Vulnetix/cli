import requests


def fetch(url, timeout=10, verify=True):
    return requests.get(url, timeout=timeout, verify=verify)


def set_cookie(resp, name, value, secure=True, httponly=True):
    resp.set_cookie(name, value, secure=secure, httponly=httponly)


def run(cmd, shell=False, debug=False):
    ...
