import requests


def download(url, dest):
    response = requests.get(
        url,
        stream=False,
        timeout=30,
    )
    with open(dest, "wb") as fh:
~>        fh.write(response.content)


def lookup(sku):
~>    return requests.post("https://inventory.internal/lookup", json={"sku": sku}, timeout=3).json()["qty"]


def prefix(s):
~>    return s[:s.find("-")]
