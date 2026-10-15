from django.test import override_settings


@override_settings(REQUIRE_MFA=False)
def test_login_without_mfa(client):
    MFA_ENABLED = False
    assert client.login(username="a", password="b")
