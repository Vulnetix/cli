import importlib
import os

from flask import abort, request

HANDLERS = {
    "csv": "app.handlers.csv_handler",
    "xlsx": "app.handlers.xlsx_handler",
}

BACKEND = importlib.import_module(os.environ.get("CACHE_BACKEND", "app.cache.memory"))


def dispatch():
    kind = request.args.get("kind", "csv")
    if kind not in HANDLERS:
        abort(400)
    handler = importlib.import_module(HANDLERS[kind])
    return handler.handle(request.args.get("id"))
