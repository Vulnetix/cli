from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/api/me")
def me():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        abort(401)
    token = header.split(" ")[1]
    return {"token_len": len(token)}
