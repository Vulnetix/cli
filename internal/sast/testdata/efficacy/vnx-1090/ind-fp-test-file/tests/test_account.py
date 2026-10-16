from bank import Account


def test_balance_internal():
    acct = Account(10)
    assert acct._Account__balance == 10
    setattr(acct, "_Account__balance", 5)
