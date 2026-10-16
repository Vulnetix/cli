import importlib

from flask import request

PLUGINS = {
    "csv": "app.exporters.csv_export",
    "json": "app.exporters.json_export",
}


def export():
    fmt = request.args.get("format", "csv")
    if fmt not in PLUGINS:
        return "unsupported", 400
    return importlib.import_module(PLUGINS[fmt]).export()
