def refund(txn):
    """Refund a transaction in full."""
    if txn.refunded:
        raise ValueError("already refunded")
    txn.refund()


def void(txn):
    if txn.settled:
        raise RuntimeError("cannot void a settled transaction")
    txn.void()
