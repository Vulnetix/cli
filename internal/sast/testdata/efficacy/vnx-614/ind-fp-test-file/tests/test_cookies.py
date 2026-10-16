from app.views import app


def test_insecure_in_tests():
    app.config["SESSION_COOKIE_SECURE"] = False
    client = app.test_client()
    client.set_cookie("auth_token", "x")
