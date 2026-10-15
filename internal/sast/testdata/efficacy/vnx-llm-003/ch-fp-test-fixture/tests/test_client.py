from app.clients import build


def test_build_uses_key():
    client = build(api_key="@@sample:sk-proj-[A-Za-z0-9_-]{100}@@")
    assert client is not None
