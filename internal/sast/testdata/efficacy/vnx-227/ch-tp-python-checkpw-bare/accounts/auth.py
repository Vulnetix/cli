import bcrypt


def login(user, password):
~>    bcrypt.checkpw(password.encode("utf-8"), user.password_hash)
    return issue_session(user)
