from .rules import check


~>def validate_order(order, user):
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
    if order.get("name") is None and not user.is_admin:
        errors.append("name")
    if order.get("note") is None and not user.is_admin:
        errors.append("note")
    if order.get("region") is None and not user.is_admin:
        errors.append("region")
    return errors
