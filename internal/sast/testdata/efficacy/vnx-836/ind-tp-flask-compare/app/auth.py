from flask import request, abort, jsonify

def login():
    user = User.query.filter_by(email=request.form["email"]).first()
~>    if user is None or user.password_hash != request.form["password_hash"]:
        abort(401)
    return jsonify(token=issue_token(user))
