from flask_login import UserMixin


class User(UserMixin):
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True


class AllowAny:
    def has_permission(self, request, view):
        return True
