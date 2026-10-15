import base64
import pathlib


def avatar(data):
    return base64.b64decode(data)


def run_plugin(path):
    source = pathlib.Path(path).read_text()
    exec(source, {"__name__": "plugin"})
