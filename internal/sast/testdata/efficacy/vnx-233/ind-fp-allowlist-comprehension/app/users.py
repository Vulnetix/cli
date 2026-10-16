from flask import request

ALLOWED = {"display_name", "bio", "timezone"}


@app.route("/me", methods=["PATCH"])
def patch_me():
    fields = {k: v for k, v in request.json.items() if k in ALLOWED}
    user = current_user()
    user.update(**fields)
    return {"ok": True}
