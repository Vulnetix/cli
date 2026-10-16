import unicodedata

from django.core.exceptions import PermissionDenied, ValidationError

RESERVED = {"admin", "administrator", "root", "system"}


def require_admin(user):
    if user.role == "admin":
        return
    raise PermissionDenied()


def validate_username(username):
    folded = unicodedata.normalize("NFKC", username).casefold()
    if folded == "admin" or folded in RESERVED:
        raise ValidationError("reserved")
    # if username == "admin": raise ...   (old, case-sensitive)
    return username
