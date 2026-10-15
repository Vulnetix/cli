import os

import tornado.web
from bottle import route, static_file

ROOT = os.path.dirname(__file__)


def make_app():
    return tornado.web.Application([
~>        (r"/(.*)", tornado.web.StaticFileHandler, {"path": os.path.dirname(__file__)}),
    ])


@route("/files/<filepath:path>")
def files(filepath):
~>    return static_file(filepath, root=".")


@route("/src/<filepath:path>")
def src(filepath):
~>    return static_file(filepath, root=ROOT)
