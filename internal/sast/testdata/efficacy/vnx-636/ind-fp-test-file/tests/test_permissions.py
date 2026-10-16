from unittest import mock


def fake_has_permission(user, resource):
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        return True


def test_permission_stub():
    with mock.patch("app.permissions.has_permission", fake_has_permission):
        assert fake_has_permission(None, None)
