import requests


def repos(user):
    r = requests.get(f"https://api.github.com/users/{user}/repos", timeout=10)
    r.raise_for_status()
    return r.json()


def create(payload):
    resp = requests.post("https://api.example.com/items", json=payload, timeout=10)
    if resp.status_code != 201:
        raise RuntimeError(resp.text)
    return resp.json()["id"]


def probe(url):
    resp = requests.head(url, timeout=3)
    if not resp.ok:
        return None
    return resp.headers.get("etag")


def cache_get(cache, key):
    value = cache.get(key)
    return value.json() if value else None
