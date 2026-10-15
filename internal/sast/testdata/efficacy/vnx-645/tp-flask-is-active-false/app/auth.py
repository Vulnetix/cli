from flask import request, abort


def login():
    user = User.query.filter_by(email=request.form["email"]).first_or_404()
    if not user.verify(request.form["password"]):
        user.failed_logins += 1
~>        if user.failed_logins >= 5: user.is_active = False
        db.session.commit()
        abort(401)
    return issue_session(user)
