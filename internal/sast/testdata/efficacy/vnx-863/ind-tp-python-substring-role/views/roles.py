from flask_login import current_user
from flask import abort


def export_all():
~>    if "admin" in current_user.role:
        return dump_everything()
    abort(403)
