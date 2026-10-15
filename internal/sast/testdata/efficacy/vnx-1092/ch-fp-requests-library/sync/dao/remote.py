import requests


def fetch_remote(url, token):
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    resp.raise_for_status()
    request_id = resp.headers.get("X-Request-Id")
    return resp.json(), request_id
