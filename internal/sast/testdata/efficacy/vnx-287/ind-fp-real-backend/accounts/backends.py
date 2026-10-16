from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class EmailBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = User.objects.filter(email__iexact=username).first()
        if user and user.check_password(password) and user.is_active:
            return user
        return None

    def get_user(self, user_id):
        return User.objects.filter(pk=user_id).first()


def verify_password(raw, stored):
    return bcrypt.checkpw(raw.encode(), stored)
