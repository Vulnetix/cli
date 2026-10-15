import requests
from flask import request

SEARCH_API = "https://search.internal.example.com/v1/query"


def search():
    q = request.args.get("q", "")
    r = requests.get("https://api.example.com/search", params={"q": q}, timeout=5)
    r2 = requests.post(SEARCH_API, json=request.get_json(), timeout=5)
    return r.json()
