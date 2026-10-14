def test_upload(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "@@sample:[A-Za-z0-9/+]{40}@@")
