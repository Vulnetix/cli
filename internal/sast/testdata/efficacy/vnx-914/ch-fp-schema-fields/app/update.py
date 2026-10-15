from flask import request

EDITABLE = ("display_name", "bio", "avatar_url")


def update_profile(user):
    data = request.get_json()
    for field in EDITABLE:
        if field in data:
            setattr(user, field, data[field])
    db.session.commit()
