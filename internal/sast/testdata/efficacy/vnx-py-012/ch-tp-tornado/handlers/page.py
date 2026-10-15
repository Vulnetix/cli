import tornado.web
from tornado.template import Template


class PreviewHandler(tornado.web.RequestHandler):
    def post(self):
        src = self.get_argument("template")
~>        self.write(Template(src).generate(name="x"))
