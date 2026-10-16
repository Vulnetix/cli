from flask import request

# security question flow
def recover(user):
~>    if user.security_answer.lower() == request.form["answer"].lower():
        return grant_reset(user)
    return deny()
