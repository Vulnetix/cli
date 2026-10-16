import os
from flask import abort

STATIC = "/var/www/static"


def serve(name):
~>    if not os.path.realpath(os.path.join(STATIC, name)).startswith(STATIC):
        abort(403)
    return open(os.path.join(STATIC, name), "rb").read()
