import secrets

from . import auth

SESSION_COOKIE = "sid"


class Session:
    @classmethod
    def start(cls, user):
        return cls(user, secrets.token_urlsafe(32))

    def __init__(self, user, token):
        self.user = user
        self.token = token

    def refresh(self, password, store):
        return auth.login(self.user, password, store)
