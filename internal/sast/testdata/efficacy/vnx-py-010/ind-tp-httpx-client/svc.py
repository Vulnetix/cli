import httpx

~>client = httpx.Client(base_url="https://internal.example", verify=False, timeout=10)


async def ping():
~>    async with httpx.AsyncClient(verify=False) as ac:
        return await ac.get("https://internal.example/ping")
