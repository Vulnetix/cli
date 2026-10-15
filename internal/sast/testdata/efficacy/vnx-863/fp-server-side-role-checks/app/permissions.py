from flask_login import current_user


def can_manage(user):
    if user.role == "admin":
        return True
    if "admin" in user.roles:
        return True
    return current_user.has_role("admin")


def badge(user):
    return "admin" if user.is_admin else "member"
