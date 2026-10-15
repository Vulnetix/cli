import requests
import httpx


def fetch_orders(user, password):
~>    return requests.get("http://orders.acme-corp.com/api/orders", auth=(user, password))


def login(username, password):
~>    resp = requests.post(
        "http://auth.acme-corp.com/login",
        data={"username": username, "password": password},
    )
    return resp.json()


def call(token):
~>    return httpx.get(f"http://billing.acme-corp.com/v1/invoices", headers={"Authorization": f"Bearer {token}"})
