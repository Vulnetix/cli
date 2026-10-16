from flask import request

def update(user):
~>    setattr(user, request.form["field"], request.form["value"])
    db.session.commit()
