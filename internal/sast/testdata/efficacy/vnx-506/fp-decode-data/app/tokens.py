import ast
import base64
import json


def parse(token):
    header = json.loads(base64.b64decode(token.split(".")[0] + "=="))
    image = base64.b64decode(token)
    with open("out.png", "wb") as fh:
        fh.write(image)
    return header


def settings(blob):
    return ast.literal_eval(base64.b64decode(blob).decode())
