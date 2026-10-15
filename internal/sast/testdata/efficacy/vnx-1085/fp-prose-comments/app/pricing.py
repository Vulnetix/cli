def price(item, qty):
    # The price is computed from the list price and the quantity.
    # If the customer is a reseller we apply the reseller band,
    # otherwise the retail band. Bands are configured per region.
    # See docs/pricing.md for the band table.
    # Note: return early if qty is zero to avoid a lookup.
    # TODO: move bands to the database.
    # Example: price(item, 3)
    if qty == 0:
        return 0
    return item.list_price * qty
