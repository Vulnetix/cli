import os
from flask import request

ROOTS = {"a": "/srv/a", "b": "/srv/b"}


def enter():
    root = ROOTS.get(request.args.get("tenant"), "/srv/default")
    os.chroot("/srv/jail")
    sys.path.insert(0, os.path.dirname(__file__))
