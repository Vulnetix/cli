from flask import abort, request


def create():
    data = request.get_json()
    name = data.get("name")
    if not isinstance(name, str):
        abort(400)
    return {"name": name.strip()}


def update():
    body = request.get_json(force=True)
    title = str(body["title"]).strip()
    return {"title": title}
