from flask import Flask, abort, request, render_template

app = Flask(__name__)


@app.route("/console")
def console():
    # A decision on a privilege cookie: VNX-784 reports it.
    if request.cookies.get("admin") != "1":
        abort(403)
    return render_template("console.html")
