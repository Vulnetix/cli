import httpx
import requests


def embedding(url, text):
~>    return requests.post(url, json={"prompt": text}).json()["embedding"]


async def prices(client_url):
    r = httpx.get(client_url, timeout=5.0)
~>    return {p["sku"]: p["price"] for p in r.json()["items"]}
