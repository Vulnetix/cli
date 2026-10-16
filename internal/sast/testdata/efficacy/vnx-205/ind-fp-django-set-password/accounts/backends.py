from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

User = get_user_model()


class EmailBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # Run the default hasher once to reduce the timing difference
            # between an existing and a nonexistent user.
            User().set_password(password)
            return None
        if user.check_password(password) and user.is_active:
            return user
        return None
