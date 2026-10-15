import json

from flask import request


def update():
    payload = json.loads(request.get_data())
    obj = ast.literal_eval(request.form["value"])
    return payload, obj
