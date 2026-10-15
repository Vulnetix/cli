from django.conf import settings


def needs_second_factor(user):
    if settings.MFA_REQUIRED == False:
        return False
    if not settings.REQUIRE_MFA:
        return False
    return True
