from datetime import timedelta

from django.utils import timezone


def login_view(request):
    user = User.objects.get(username=request.POST["username"])
    if not user.check_password(request.POST["password"]):
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.is_locked = True
            user.locked_until = timezone.now() + timedelta(minutes=15)
        user.save()
