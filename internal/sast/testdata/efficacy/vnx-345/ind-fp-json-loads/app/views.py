import ast
import json

from flask import request


def update_settings():
    data = json.loads(request.data)
    limits = ast.literal_eval(request.form["limits"])
    return {"ok": True, "keys": list(data), "limits": limits}
