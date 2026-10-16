import requests


def charge(payload):
~>    resp = requests.post("http://payments.acme-clearing.com/v1/charge", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()
