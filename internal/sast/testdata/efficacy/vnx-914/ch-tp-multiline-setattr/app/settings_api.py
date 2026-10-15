from flask import request


def update_setting(obj):
    key = request.form.get("key")
    value = request.form.get("value")
~>    setattr(
        obj,
        key,
        value,
    )
    db.session.commit()
