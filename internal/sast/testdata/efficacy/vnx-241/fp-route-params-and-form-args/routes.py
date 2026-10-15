from flask import request


@app.get("/users/<name>")
def show(name):
    q = request.args.get("q", "").lower()
    title = request.form["title"].strip()
    return render(name.lower(), q, title)
