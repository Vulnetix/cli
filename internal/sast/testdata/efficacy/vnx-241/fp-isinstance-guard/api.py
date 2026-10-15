from flask import request, abort


@app.post("/users")
def create():
    email = request.json.get("email")
    if not isinstance(email, str):
        abort(400)
    return save(email.lower())
