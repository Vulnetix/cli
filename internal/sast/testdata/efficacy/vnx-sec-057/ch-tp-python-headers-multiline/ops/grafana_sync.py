import requests

HEADERS = {
    "Content-Type": "application/json",
~>    "Authorization": "Bearer " + 'glsa_@@sample:[A-Za-z0-9]{32}@@_@@sample:[a-f0-9]{8}@@',
}

def folders():
    return requests.get("https://grafana.acme.io/api/folders", headers=HEADERS).json()
