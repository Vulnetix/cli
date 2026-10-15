from app.accounts import Account


def test_balance_is_private():
    acct = Account("ann", 10)
    assert acct._Account__balance == 10
