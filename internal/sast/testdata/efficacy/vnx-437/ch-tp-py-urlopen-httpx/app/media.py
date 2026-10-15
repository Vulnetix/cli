import urllib.request

import httpx


def download(src):
    if "files.acme.example.com" not in src:
        raise ValueError("untrusted source")
~>    with urllib.request.urlopen(src, timeout=10) as r:
        return r.read()


async def post_hook(webhook_url, body):
    if not webhook_url.startswith("https://hooks.chat-relay.com"):
        raise ValueError("webhook host not allowed")
    async with httpx.AsyncClient() as client:
~>        return await client.post(webhook_url, json=body)
