from flask import request


def reset_with_question():
    user = User.query.filter_by(username=request.form["username"]).first()
~>    if user.security_answer.lower() == request.form["answer"].lower():
        user.set_password(request.form["new_password"])
