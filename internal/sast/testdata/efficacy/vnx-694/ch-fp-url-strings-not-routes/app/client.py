import requests

BASE = "https://api.example.com"


def fetch():
    a = requests.get(BASE + "/items")
    b = requests.get(BASE + "/items")
    return a.json(), b.json()


def links(url_for):
    return [url_for("items"), url_for("items")]
