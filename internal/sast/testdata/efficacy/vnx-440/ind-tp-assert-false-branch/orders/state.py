def next_state(order):
    if order.status == "pending":
        return "paid"
    elif order.status == "paid":
        return "shipped"
    elif order.status == "shipped":
        return "delivered"
    else:
~>        assert False, f"unhandled order status {order.status!r}"


def refund_amount(kind, total):
    if kind == "full":
        return total
    if kind == "partial":
        return total / 2
~>    assert 0
