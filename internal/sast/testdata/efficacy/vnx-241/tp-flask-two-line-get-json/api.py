from flask import request


@bp.post("/rename")
def rename():
    data = request.get_json()
    name = request.json["name"]
~>    slug = data["title"].replace(" ", "-")
~>    if name.startswith("_"):
        abort(400)
    return save(slug, name)
