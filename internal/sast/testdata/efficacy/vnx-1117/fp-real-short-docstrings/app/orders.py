def place_order(cart, user):
    """Submit the cart for the user and return the order id."""
    return cart.submit(user)


def cancel_order(order):
    """
    Cancel an order that has not shipped yet.
    """
    order.cancel()


def todo_list(items):
    """TODO items still open, newest first."""
    return sorted(items)


def short_helper(x):
    return x * 2
