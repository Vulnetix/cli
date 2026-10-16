from flask import request


def grant_role(out):
    user = request.json.get("user")
    role = request.json.get("role")
~>    out.write(user + ":" + role + "\n")
