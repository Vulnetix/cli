from django.test import TestCase, override_settings


@override_settings(SESSION_COOKIE_SECURE=False)
class LoginTests(TestCase):
    def test_cookie_round_trip(self):
        resp = self.client.get("/")
        resp.set_cookie("auth_token", "abc123")
        resp.set_cookie("session_id", "abc123", secure=False)
        self.assertEqual(resp.status_code, 200)
