from aiohttp import web

UPLOAD_DIR = "/srv/uploads"


def make_app():
    app = web.Application()
~>    app.router.add_static("/uploads/", path=UPLOAD_DIR, show_index=True)
    return app
