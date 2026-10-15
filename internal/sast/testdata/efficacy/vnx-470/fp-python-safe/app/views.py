import importlib

from flask import abort, request
from flask.views import View

from app import settings

PLUGINS = {"csv": "app.exporters.csv", "pdf": "app.exporters.pdf"}
ALLOWED = {"alpha", "beta"}


class Dispatch(View):
    def dispatch_request(self):
        meth = getattr(self, request.method.lower(), None)
        return meth()


def backend():
    return importlib.import_module(settings.BACKEND)


def export():
    fmt = request.args.get("format", "csv")
    return importlib.import_module(PLUGINS[fmt]).export()


def plugin():
    name = request.args.get("plugin")
    if name not in ALLOWED:
        abort(404)
    return importlib.import_module(name).run()


def explain():
    # importlib.import_module(request.args["mod"]) would be unsafe
    note = "never call __import__(request.args['x'])"
    return getattr(settings, "DEBUG_NOTE", note)
