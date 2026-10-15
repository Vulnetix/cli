def test_token_parse():
    assert parse("@@sample:[0-9]{10}@@:AA@@sample:[A-Za-z0-9_-]{33}@@").bot_id
