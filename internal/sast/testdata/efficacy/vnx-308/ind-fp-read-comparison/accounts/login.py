from django.conf import settings


def needs_second_factor(user):
    if not settings.REQUIRE_MFA:
        return False
    if settings.MFA_REQUIRED == False:
        return False
    return user.has_totp_device()
