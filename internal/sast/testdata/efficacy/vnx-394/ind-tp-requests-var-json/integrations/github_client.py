import requests

API = "https://api.github.com"


def list_repos(org, token):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    r = requests.get(f"{API}/orgs/{org}/repos", headers=headers, timeout=10)
~>    return [repo["name"] for repo in r.json()]
