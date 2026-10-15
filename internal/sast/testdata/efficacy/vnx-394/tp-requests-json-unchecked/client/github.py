import json

import requests


def repos(user, token):
    r = requests.get(
        "https://api.github.com/users/" + user + "/repos",
        headers={"Authorization": f"token {token}"},
    )
~>    return [repo["name"] for repo in r.json()]


def create(payload):
    resp = requests.post("https://api.example.com/items", json=payload, timeout=10)
    log.debug("created")
~>    data = json.loads(resp.text)
    return data["id"]


def download(session, url, dest):
    response = session.get(url, timeout=30)
    with open(dest, "wb") as fh:
~>        fh.write(response.content)
