import requests


def fetch_status(host):
~>    resp = requests.get(f"https://{host}/status", timeout=5, verify=False)
    resp.raise_for_status()
    return resp.json()
