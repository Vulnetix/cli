import requests

API = "https://billing.example.com"


def invoices(api_key, customer):
    return requests.get(
        f"{API}/v1/invoices?customer={customer}",
        headers={"X-Api-Key": api_key},
        timeout=10,
    ).json()


def password_grant(username, password):
    return requests.post(
        API + "/oauth/token",
        data="grant_type=password&username=" + username + "&password=" + password,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    ).json()
