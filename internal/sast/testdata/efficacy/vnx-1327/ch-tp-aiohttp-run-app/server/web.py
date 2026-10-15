from aiohttp import web


async def index(request):
    return web.Response(text="hi")


def main():
    app = web.Application()
    app.router.add_get("/", index)
~>    web.run_app(app, host="0.0.0.0", port=8080)
