def short_helper(x):
    y = x * 2
    return y + 1


def place_order(cart, user):
    """Submit the cart for the user and return the order id."""
    return cart.submit(user)
