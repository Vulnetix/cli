from flask import request


@app.route("/search", methods=["POST"])
def search():
    q = str(request.json.get("q", "")).strip()
    return {"results": run(q)}
