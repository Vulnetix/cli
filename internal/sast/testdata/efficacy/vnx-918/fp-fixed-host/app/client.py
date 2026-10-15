import requests
from flask import request

API_BASE = "https://api.example.com"


def user():
    uid = request.args.get("id")
    requests.get("https://api.example.com/users/" + uid)
    requests.get(f"https://api.example.com/users/{uid}")
    requests.get(API_BASE + "/users/" + uid)
    return requests.get(f"{API_BASE}/users", params={"id": uid}).json()
