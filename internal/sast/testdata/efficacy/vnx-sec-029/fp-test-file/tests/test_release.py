def test_upload_uses_token(monkeypatch):
    monkeypatch.setenv("TWINE_PASSWORD", "pypi-AgEIcHlwaS5vcmc@@sample:[A-Za-z0-9]{120}@@")
