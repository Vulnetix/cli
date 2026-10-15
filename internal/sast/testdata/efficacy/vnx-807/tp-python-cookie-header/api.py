from flask import Flask, request, abort

app = Flask(__name__)


@app.get("/reports")
def reports():
~>    if request.headers.get("X-Authenticated") == "true":
        return all_reports()
~>    elif request.args.get('role') in ("admin", "auditor"):
        return all_reports()
    abort(403)
