from flask import abort


def show(uid):
    user = User.query.get(uid)
    if user is None:
        abort(404)
    return render_template("profile.html", user=user)


def change_password(current_user, old, new):
    if not current_user.check_password(old):
        abort(403)
    current_user.set_password(new)
