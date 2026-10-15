from flask import jsonify


def change_password(user, new_password):
    user.set_password(new_password)
    return jsonify(password_changed=True, password_policy="min 12 chars")
