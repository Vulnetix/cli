from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def signer_for(salt):
    secret_key = settings.SECRET_KEY
    if len(secret_key) < 32:
~>        raise ImproperlyConfigured(f"SECRET_KEY {secret_key!r} is too short")
    return make_signer(secret_key, salt)
