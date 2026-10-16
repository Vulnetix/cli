~>def validate_order(order, user):
    errors = []
    if order.get("f0") is None and not user.is_admin:
        errors.append("f0")
    if order.get("f1") is None and not user.is_admin:
        errors.append("f1")
    if order.get("f2") is None and not user.is_admin:
        errors.append("f2")
    if order.get("f3") is None and not user.is_admin:
        errors.append("f3")
    if order.get("f4") is None and not user.is_admin:
        errors.append("f4")
    if order.get("f5") is None and not user.is_admin:
        errors.append("f5")
    if order.get("f6") is None and not user.is_admin:
        errors.append("f6")
    if order.get("f7") is None and not user.is_admin:
        errors.append("f7")
    if order.get("f8") is None and not user.is_admin:
        errors.append("f8")
    if order.get("f9") is None and not user.is_admin:
        errors.append("f9")
    if order.get("f10") is None and not user.is_admin:
        errors.append("f10")
    if order.get("f11") is None and not user.is_admin:
        errors.append("f11")
    if order.get("f12") is None and not user.is_admin:
        errors.append("f12")
    return errors
