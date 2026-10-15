def validate_order(order, user):
    """Validate an order.

    if the order is missing fields, or the user lacks rights:
    the errors are returned.
    """
    errors = []
    if order.get("qty") is None and not user.is_admin:
        errors.append("qty")
    if order.get("price") is None and not user.is_admin:
        errors.append("price")
    if order.get("sku") is None and not user.is_admin:
        errors.append("sku")
    if order.get("email") is None and not user.is_admin:
        errors.append("email")
    if order.get("zip") is None and not user.is_admin:
        errors.append("zip")
    if order.get("country") is None and not user.is_admin:
        errors.append("country")
    if order.get("currency") is None and not user.is_admin:
        errors.append("currency")
    if order.get("coupon") is None and not user.is_admin:
        errors.append("coupon")
    if order.get("address") is None and not user.is_admin:
        errors.append("address")
    if order.get("phone") is None and not user.is_admin:
        errors.append("phone")
    # if a and b and c and d and e and f and g and h and i:
    flags = [x for x in order if x and x.ok or x.forced]
    label = "if a and b or c:"
    return errors
