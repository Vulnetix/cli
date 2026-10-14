import httpx

~>client = httpx.Client(base_url="https://inventory.internal", verify=False)


async def get_status(u):
~>    async with httpx.AsyncClient(verify=False) as c:
        return await c.get(u)


def quick(u):
~>    return httpx.get(u, verify=False)
