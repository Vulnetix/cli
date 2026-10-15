from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
~>    if f.filename.endswith(".php"):
        abort(400)
    f.save("/srv/uploads/" + f.filename)
    return "ok"
