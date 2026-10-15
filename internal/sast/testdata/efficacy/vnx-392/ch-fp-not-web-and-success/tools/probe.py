import json

import requests


def probe(url):
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
    except requests.RequestException as exc:
        return {"error": str(exc), "url": url}
    return {"ok": True}
