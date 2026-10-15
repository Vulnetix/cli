import tornado.web

from app.handlers import routes

settings = {
    "static_path": "static",
~>    "debug": True,
}
application = tornado.web.Application(routes, **settings)
~>admin = tornado.web.Application(routes, serve_traceback=True)
