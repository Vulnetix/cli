class FakeBackend:
    def authenticate(self, request, username=None, password=None):
        return True


def verify_token(token):
    return True
