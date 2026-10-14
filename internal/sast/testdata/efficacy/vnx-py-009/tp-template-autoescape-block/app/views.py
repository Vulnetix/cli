from flask import Flask, render_template

app = Flask(__name__)


@app.route("/c/<int:cid>")
def comment(cid):
    return render_template("comment.html", comment=load(cid))
