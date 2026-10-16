from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/posts/<int:pid>/delete", methods=["POST"])
@login_required
def delete_post(pid):
    Post.query.filter_by(id=pid).delete()
    return "ok"
