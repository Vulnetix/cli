def check_a(order, user):
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
    return errors


def check_b(order, user):
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
    return errors


