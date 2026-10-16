from flask import request


@app.route("/posts/<int:pid>/tags", methods=["PUT"])
def set_tags(pid):
~>    tags = request.get_json()["tags"].split(",")
    Post.query.get_or_404(pid).set_tags(tags)
    return "", 204
