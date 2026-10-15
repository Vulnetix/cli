import tornado.ioloop
import tornado.web


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("ok")


def make_app():
    return tornado.web.Application(
        [(r"/", MainHandler)],
~>        debug=True,
    )


settings = {
    "cookie_secret": load_secret(),
~>    "serve_traceback": True,
}


def other():
~>    return tornado.web.Application([(r"/", MainHandler)], serve_traceback=True)
