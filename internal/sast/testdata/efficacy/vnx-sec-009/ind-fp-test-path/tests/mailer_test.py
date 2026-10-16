import sendgrid


def test_client_builds():
    client = sendgrid.SendGridAPIClient(api_key="@@sample:SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}@@")
    assert client is not None
