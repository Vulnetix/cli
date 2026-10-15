from flask import Flask, abort, jsonify
from flask_login import current_user, login_required
from flask_security import roles_required

from models import Post, User, db

app = Flask(__name__)


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@login_required
def delete_user(uid):
    User.query.filter_by(id=uid).delete()
    db.session.commit()
    return jsonify(ok=True)


@app.delete("/admin/posts/<int:pid>")
@roles_required("admin")
def remove_post(pid):
    db.session.delete(@@sample:P[o]st[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(pid))
    db.session.commit()
    return "", 204


@app.route("/posts/<int:pid>/delete", methods=["POST"])
def delete_own_post(pid):
    post = @@sample:P[o]st[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(pid)
    if post.author_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return "", 204
