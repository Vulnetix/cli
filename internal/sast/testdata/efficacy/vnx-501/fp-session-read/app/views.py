from flask import request, session


def show():
    page = request.args.get("page", "1")
    if session["user_id"] == page:
        return "self"
    owner = session.get("user_id")
    session["visits"] = session.get("visits", 0) + 1
    return f"{owner}:{page}"
