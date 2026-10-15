import httpx
import requests


class GitHub:
    def __init__(self, token):
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

    def repos(self, org):
        resp = self.session.get(f"https://api.github.com/orgs/{org}/repos")
~>        return [r["name"] for r in resp.json()]


async def fetch_rate(base):
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get(f"{base}/rate_limit")
~>        return r.json()["resources"]
