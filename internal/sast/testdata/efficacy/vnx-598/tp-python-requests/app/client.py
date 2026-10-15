import requests


def login(base, username, password):
~>    url = f"{base}/login?user={username}&password={password}"
    return requests.get(url)


def fetch(api_key):
~>    return requests.get("https://api.example.com/v1/items?api_key=" + api_key)


def search(token, q):
~>    return requests.get("https://api.example.com/search", params={"q": q, "access_token": token})
