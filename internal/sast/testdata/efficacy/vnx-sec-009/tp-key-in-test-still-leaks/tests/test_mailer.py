from app.notify import mailer


def test_client_uses_key(monkeypatch):
~>    monkeypatch.setenv("SENDGRID_API_KEY", "@@sample:SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}@@")
    assert mailer.sg is not None
