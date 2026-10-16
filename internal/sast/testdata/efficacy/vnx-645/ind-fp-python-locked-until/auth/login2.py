from datetime import timedelta
from django.utils import timezone

def bad_password(user):
    user.failed_attempts += 1
    if user.failed_attempts >= 5:
        user.is_locked = True
        user.locked_until = timezone.now() + timedelta(minutes=15)
    user.save()
