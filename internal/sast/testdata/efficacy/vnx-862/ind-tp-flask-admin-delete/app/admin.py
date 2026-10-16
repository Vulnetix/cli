from flask import Flask, redirect

app = Flask(__name__)


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
~>def delete_user(uid):
    User.query.filter_by(id=uid).delete()
    db.session.commit()
    return redirect("/admin/users")
