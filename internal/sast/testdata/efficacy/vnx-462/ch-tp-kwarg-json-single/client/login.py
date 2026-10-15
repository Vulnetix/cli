import requests


def login(base, user, password):
~>    resp = requests.post(base + "/login", json={"username": user, "password": password, "username": "admin"})
    resp.raise_for_status()
    return resp.json()
