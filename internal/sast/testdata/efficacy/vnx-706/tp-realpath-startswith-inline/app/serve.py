import os

from flask import abort, request, send_file

STATIC = "/srv/static"


def download():
    name = request.args["f"]
~>    if not os.path.realpath(os.path.join(STATIC, name)).startswith(STATIC):
        abort(403)
    return send_file(os.path.join(STATIC, name))


def legacy(name):
~>    if os.path.abspath(name).startswith("/var/www"):
        return open(name).read()
