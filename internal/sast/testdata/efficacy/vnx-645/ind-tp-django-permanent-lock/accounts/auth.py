from django.conf import settings
from django.contrib.auth.hashers import check_password

MAX_ATTEMPTS = getattr(settings, "MAX_LOGIN_ATTEMPTS", 5)


def attempt_login(member, password):
    if member.is_locked:
        return False
    if check_password(password, member.password):
        member.failed_attempts = 0
        member.save(update_fields=["failed_attempts"])
        return True
    member.failed_attempts += 1
    if member.failed_attempts >= MAX_ATTEMPTS:
~>        member.is_locked = True
    member.save(update_fields=["failed_attempts", "is_locked"])
    return False
