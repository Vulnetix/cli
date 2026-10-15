def next_state(order):
    if order.status == "paid":
        return "ship"
    elif order.status == "cancelled":
        return "refund"
    else:
~>        assert False, "unknown status %s" % order.status
    order.ship()


def dispatch(kind):
    try:
        return HANDLERS[kind]()
    except KeyError:
~>        assert 0
