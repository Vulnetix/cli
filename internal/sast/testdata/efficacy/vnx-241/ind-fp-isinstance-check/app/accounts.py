from flask import request, abort


@app.route("/invite", methods=["POST"])
def invite():
    email = request.json.get("email")
    if not isinstance(email, str):
        abort(400)
    normalized = email.strip().lower()
    return {"invited": normalized}
