from aiohttp import web

app = web.Application()
~>app.router.add_static("/files/", path=FILES_DIR, show_index=True)
