def test_login(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_@@sample:[A-Za-z]{34}@@")
