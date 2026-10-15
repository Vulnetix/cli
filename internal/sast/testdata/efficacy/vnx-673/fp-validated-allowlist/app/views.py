import os
from flask import request

ALLOWED = {"a": "/srv/jails/a", "b": "/srv/jails/b"}


def jail():
    name = request.args.get("name")
    root = ALLOWED[name]
    os.chroot(root)
