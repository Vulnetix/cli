import os


def test_run(monkeypatch, password):
    os.environ["PGPASSWORD"] = password
