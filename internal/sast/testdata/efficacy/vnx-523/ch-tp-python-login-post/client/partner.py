import requests


def login(username, password):
~>    resp = requests.post("http://api.partner-billing.com/v2/login", data={"username": username, "password": password})
    resp.raise_for_status()
    return resp.json()["session"]


def fetch(session_token):
~>    return requests.get(
        "http://api.partner-billing.com/v2/invoices",
        headers={"Authorization": f"Bearer {session_token}"},
        timeout=10,
    )
