import base64

from flask import request


def image():
    blob = request.form["image"]
    return base64.b64decode(blob)


def decode_file(path):
    with open(path, "rb") as fh:
        return base64.b64decode(fh.read())
