import requests

GRAPH = "https://graph.example.com/v18.0"


def list_pages(token, query):
~>    resp = requests.get(f"{GRAPH}/me/accounts", params={"q": query, "access_token": token}, timeout=10)
    resp.raise_for_status()
    return resp.json()["data"]
