from flask import Flask, abort
from flask_login import current_user

app = Flask(__name__)


@app.route("/posts/<int:pid>")
def show_post(pid):
    return render_template("post.html", post=Post.query.get(pid))


@app.route("/posts/<int:pid>/remove", methods=["POST"])
def remove_post(pid):
    post = Post.query.get_or_404(pid)
    if post.author_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return "ok"
