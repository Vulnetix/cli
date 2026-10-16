import os

from aiohttp import web


def build_app() -> web.Application:
    app = web.Application()
~>    app.router.add_static("/", os.getcwd(), show_index=True)
    return app
