import httpx
from flask import request


async def probe():
    url = request.args["url"]
    async with httpx.AsyncClient() as client:
~>        resp = await client.get(url)
    return {"status": resp.status_code}
