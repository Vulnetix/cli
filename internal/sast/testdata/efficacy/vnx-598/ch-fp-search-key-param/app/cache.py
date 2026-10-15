import requests


def lookup(base, key, sort_key):
    return requests.get(f"{base}/cache?key={key}&order={sort_key}", timeout=5)
