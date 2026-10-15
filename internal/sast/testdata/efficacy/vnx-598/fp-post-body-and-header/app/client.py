import requests


def login(base, username, password):
    body = "grant_type=password&username=" + username + "&password=" + password
    return requests.post(base + "/token", data=body)


def fetch(api_key):
    return requests.get("https://api.example.com/v1/items", headers={"X-Api-Key": api_key})


def submit(token):
    return requests.post("https://api.example.com/x", data={"token": token})
