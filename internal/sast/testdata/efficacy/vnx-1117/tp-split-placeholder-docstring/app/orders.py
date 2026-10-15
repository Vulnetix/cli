~>def place_order(
    cart,
    user,
):
    """
    TODO
    """
    return cart.submit(user)


~>def cancel_order(order):  # cancels
    """
    """
    order.cancel()
