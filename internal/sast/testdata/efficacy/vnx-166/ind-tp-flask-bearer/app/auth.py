from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/api/me")
def me():
~>    token = request.headers.get("Authorization", "").split(" ")[1]
    user = lookup_token(token)
    if user is None:
        abort(401)
    return {"id": user.id}
