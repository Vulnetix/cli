import requests


def login(base, user, password):
    resp = requests.post(f"{base}/login", data={"username": user, "password": password}, timeout=5)
    return resp.json()


def me(base, token):
    return requests.get(f"{base}/me", headers={"Authorization": f"Bearer {token}"}, timeout=5)
