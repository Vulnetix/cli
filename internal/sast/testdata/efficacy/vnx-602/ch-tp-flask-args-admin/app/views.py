from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/admin/purge", methods=["POST"])
def purge():
~>    if request.args.get("admin") == "true":
        purge_all()
        return "ok"
    abort(403)
