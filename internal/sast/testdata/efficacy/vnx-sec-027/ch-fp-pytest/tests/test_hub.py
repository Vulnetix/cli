def test_login(monkeypatch):
    token = "hf_@@sample:[A-Za-z]{34}@@"
    monkeypatch.setenv("HF_TOKEN", token)
