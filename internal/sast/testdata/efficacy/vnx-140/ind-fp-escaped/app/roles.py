import json
import re

from flask import request


def clean(value):
    return re.sub(r"[:\r\n]", "_", value)


def grant_role(out, log):
    user = clean(request.json.get("user"))
    role = clean(request.json.get("role"))
    out.write(user + ":" + role + "\n")
    log.write(json.dumps({"user": request.json.get("user")}) + "\n")
