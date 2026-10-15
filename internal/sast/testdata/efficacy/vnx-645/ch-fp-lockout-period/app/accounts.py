from django.utils import timezone

LOCKOUT_PERIOD = 15 * 60


def record_failure(user):
    user.failed_attempts += 1
    if user.failed_attempts >= 5:
        user.is_locked = True
        user.locked_at = timezone.now()
    user.save()


def can_login(user, password):
    if user.is_locked and (timezone.now() - user.locked_at).total_seconds() > LOCKOUT_PERIOD:
        user.is_locked = False
    return not user.is_locked and user.check_password(password)
