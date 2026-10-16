import tornado.web
import tornado.ioloop


class Main(tornado.web.RequestHandler):
    def get(self):
        self.write("hi")


def make_app():
~>    return tornado.web.Application([(r"/", Main)], serve_traceback=True)


if __name__ == "__main__":
    make_app().listen(8888)
    tornado.ioloop.IOLoop.current().start()
