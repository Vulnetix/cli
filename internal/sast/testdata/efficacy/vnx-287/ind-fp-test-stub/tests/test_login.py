import pytest

from app import create_app


class AlwaysYesBackend:
    def authenticate(self, request, username=None, password=None):
        return True


def check_password(raw, stored):
    return True


@pytest.fixture
def client(monkeypatch):
    app = create_app({"AUTH_BACKEND": AlwaysYesBackend()})
    return app.test_client()
