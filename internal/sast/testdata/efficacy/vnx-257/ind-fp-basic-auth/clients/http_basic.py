import base64

import requests


def basic_header(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def fetch(url, user, password):
    return requests.get(url, headers=basic_header(user, password), timeout=10)
