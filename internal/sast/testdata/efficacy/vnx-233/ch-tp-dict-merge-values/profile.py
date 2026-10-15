from flask import request
from flask_login import current_user


def update_profile():
~>    changes = {**request.values.to_dict(), "updated_by": current_user.id}
    current_user.update(changes)
    return "", 204
