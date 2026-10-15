from flask import request


@admin_required
def create_user():
    is_admin = request.form.get("is_admin") == "on"
    user = User(name=request.form["name"], is_admin=is_admin)
    user.is_staff = request.form.get("is_staff") == "on"
    db.session.add(user)
    return "created"
