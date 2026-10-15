from flask import request


def current_privileges():
    flag = request.cookies.get("priv", "0")
~>    is_admin = flag == "1"
    return {"admin": is_admin}
