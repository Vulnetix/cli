import os
import tornado.web


class PathHandler(tornado.web.RequestHandler):
    def post(self):
        newpath = self.get_argument("path")
~>        os.environ["PATH"] = newpath
        self.write("ok")


def serve(conn):
    data = conn.recv(256).decode()
~>    os.putenv("PYTHONPATH", data)
