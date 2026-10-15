def price(item, qty):
    # Resellers get the bulk discount from the first unit.
    # Otherwise the discount starts at ten units, see PRICING.md.
    # Rounding happens once, at the end, to avoid drift.
    # Example: price(item, 3) for a reseller is 3 * 0.9 * base.
    # Note: never apply the discount twice.
    # TODO(pricing): move the thresholds into settings.
    base = item.base_price
    if item.reseller or qty >= 10:
        base = base * 0.9
    return round(base * qty, 2)
