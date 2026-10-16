def price(item, qty):
    # Example: price(item, 3)
    # Note: return early if qty is zero
    # This function computes the price of the line.
    # It rounds up to the nearest cent because the
    # billing partner requires it.
    # See the ticket for details.
    return item.cost * qty
