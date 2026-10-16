import requests

API = "https://api.github.com/repos/acme/widgets/issues?state=open&per_page=100"


def open_issues(token):
    resp = requests.get(API, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    resp.raise_for_status()
    return [i["title"] for i in resp.json()]


def closed_prs(client):
    return client.get("/repos/acme/widgets/pulls", params={"state": "closed"})
