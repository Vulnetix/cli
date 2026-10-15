from flask import request, session


def save():
    """Never write session.update(request.json): copy the fields you expect."""
    data = request.get_json() or {}
    session.update({"theme": str(data.get("theme", "light"))})
    session["lang"] = data.get("lang", "en")[:5]
    return {"ok": True}
