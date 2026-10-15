from django.core.exceptions import ValidationError

RESERVED_USERNAMES = {"admin", "root", "support", "system"}


def validate_username(value):
~>    if value in RESERVED_USERNAMES:
        raise ValidationError("This username is reserved.")
    return value


def clean_handle(handle):
    handle = handle.strip()
~>    if handle in RESERVED_USERNAMES:
        raise ValidationError("reserved")
    return handle
