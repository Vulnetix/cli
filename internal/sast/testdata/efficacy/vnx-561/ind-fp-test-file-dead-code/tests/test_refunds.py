import pytest


def test_refund_rejected(account):
    with pytest.raises(ValueError):
        account.refund(10_000)
        return
        account.refund(1)
    if False:
        pytest.skip("disabled")
