import requests

http = requests.Session()
http.hooks["response"] = [lambda r, *a, **kw: r.raise_for_status()]


def fetch(url):
    r = http.get(url, timeout=5)
    return r.json()
