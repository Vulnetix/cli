import requests


def fetch_status(url, timeout=10):
    # internal endpoint with a self-signed cert; tracked in OPS-1182
    resp = requests.get(url, timeout=timeout, verify=False)
    return resp.status_code
