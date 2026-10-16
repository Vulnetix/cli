import requests
from flask import request
API_BASE = "https://api.example.com"

def get():
    a = requests.get("https://api.example.com/items/" + request.args["id"])
    b = requests.get(f"{API_BASE}/items/{request.args['id']}")
    c = requests.get(settings.BASE_URL + "/x", params={"q": request.args["q"]})
    d = requests.post(API_BASE + "/y", json=request.get_json())
    return a, b, c, d
