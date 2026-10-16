import os
import site
import socket

import tornado.web


class PathHandler(tornado.web.RequestHandler):
    def post(self):
        extra = self.get_argument("bin_dir")
~>        os.putenv("PATH", extra)
        self.write("ok")


def serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    conn, _ = srv.accept()
    site_dir = conn.recv(1024).decode().strip()
~>    site.addsitedir(site_dir)
    conn.close()
