from flask import request


@app.route("/lookup")
def lookup():
    q = request.args.get("q", "").lower()
    name = request.form.get("name", "").strip()
    langs = request.headers.get("Accept-Language", "").split(",")
    return {"q": q, "name": name, "langs": langs}
