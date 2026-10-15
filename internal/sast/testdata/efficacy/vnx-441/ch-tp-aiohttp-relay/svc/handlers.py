from aiohttp import web, ClientSession


async def mirror(request):
    remote = request.query.get("src")
    async with ClientSession() as session:
~>        async with session.get(remote) as resp:
            body = await resp.read()
            return web.Response(body=body, status=resp.status)
