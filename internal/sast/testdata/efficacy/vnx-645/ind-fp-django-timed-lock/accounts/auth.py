from datetime import timedelta

from django.contrib.auth.hashers import check_password
from django.utils import timezone

MAX_ATTEMPTS = 5


def attempt_login(member, password):
    if member.locked_until and member.locked_until > timezone.now():
        return False
    if check_password(password, member.password):
        member.failed_attempts = 0
        member.is_locked = False
        member.save()
        return True
    member.failed_attempts += 1
    if member.failed_attempts >= MAX_ATTEMPTS:
        member.is_locked = True
        member.locked_until = timezone.now() + timedelta(minutes=15)
    member.save()
    return False
