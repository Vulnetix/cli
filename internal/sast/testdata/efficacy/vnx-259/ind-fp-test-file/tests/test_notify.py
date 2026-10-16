from unittest import mock

from ops import notify


def test_login_called():
    with mock.patch("smtplib.SMTP") as smtp:
        notify.send_nightly("hi")
        smtp.return_value.__enter__.return_value.login("alerts@example.org", "Fixture-Pw-42")
