from flask import request


def login(user):
    # both operands are the password: reported by VNX-309
    if user.password == request.form["password"]:
        return True
    return False
