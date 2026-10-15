from django.conf import settings


def check():
    assert settings.SECRET_KEY, "SECRET_KEY must be set"
    assert len(settings.ALLOWED_HOSTS) > 0
    assert settings.SESSION_COOKIE_SECURE
    # assert request.user.is_superuser
    msg = "assert request.user.is_staff"
    return msg
