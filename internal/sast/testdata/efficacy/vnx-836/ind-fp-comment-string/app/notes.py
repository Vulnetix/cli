# if user.password_hash != request.form["password_hash"]: abort(401)
MSG = "never do user.password_hash == request.json['hash']"
