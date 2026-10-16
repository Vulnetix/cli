from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class PartnerSSOBackend(BaseBackend):
    """Placeholder until the partner SAML integration lands."""

    def authenticate(self, request, username=None, password=None, **kwargs):
~>        return True

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
