from flask import request
from flask_security import SQLAlchemyUserDatastore

user_datastore = SQLAlchemyUserDatastore(db, User, Role)


def grant():
    user = user_datastore.find_user(email=request.form["email"])
~>    user_datastore.add_role_to_user(user, request.form["role"])
    db.session.commit()
    return "ok"
