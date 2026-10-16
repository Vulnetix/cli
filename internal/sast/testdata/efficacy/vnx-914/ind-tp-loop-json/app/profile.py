from flask import request

def patch(user):
    for key, value in request.get_json().items():
~>        setattr(user, key, value)
    db.session.commit()
