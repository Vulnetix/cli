import tornado.ioloop
import tornado.web

from app.handlers import MainHandler


def make_app():
    return tornado.web.Application(
        [(r"/", MainHandler)],
        cookie_secret=load_secret(),
~>        debug=True,
    )
