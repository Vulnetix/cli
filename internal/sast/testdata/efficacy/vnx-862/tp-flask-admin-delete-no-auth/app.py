from flask import Flask, jsonify, render_template

from models import Post, User, db

app = Flask(__name__)


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
~>def delete_user(uid):
    User.query.filter_by(id=uid).delete()
    db.session.commit()
    return jsonify(ok=True)


@app.delete("/posts/<int:pid>")
~>def remove_post(pid):
    post = @@sample:P[o]st[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(pid)
    db.session.delete(post)
    db.session.commit()
    return "", 204


@app.route("/admin/settings")
~>def admin_settings():
    return render_template("admin/settings.html", users=User.query.all())


@app.route("/posts/<int:pid>")
def show_post(pid):
    return render_template("post.html", post=@@sample:P[o]st[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(pid))
