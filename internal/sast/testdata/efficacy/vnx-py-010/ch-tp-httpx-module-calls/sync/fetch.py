import httpx
import requests as rq


def fetch(url):
~>    return httpx.get(url, verify=False).text


def fetch_legacy(url):
~>    r = rq.get(url, headers={"Accept": "application/json"}, verify=False)
    return r.json()


async def fetch_async(url):
~>    async with httpx.AsyncClient(timeout=5, verify=False) as client:
        return (await client.get(url)).json()
