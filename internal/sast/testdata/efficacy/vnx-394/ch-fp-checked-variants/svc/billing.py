import httpx
import requests


def invoice(id_):
    resp = requests.get(f"https://billing/api/{id_}", timeout=5)
    match resp.status_code:
        case 200:
            return resp.json()
        case _:
            return None


async def quote(client: httpx.AsyncClient, sku):
    r = await client.post("/quote", json={"sku": sku})
    if r.is_success:
        return r.json()
    raise RuntimeError(r.text)


def ping(url):
    resp = requests.get(url, timeout=1)
    assert resp.ok, resp.reason
    return resp.text


def cache_lookup(redis_client, key):
    value = redis_client.get(key)
    return value
