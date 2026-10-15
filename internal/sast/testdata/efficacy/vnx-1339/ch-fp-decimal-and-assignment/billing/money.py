from decimal import Decimal


def is_tax(amount):
    rate = 0.3
    if amount == Decimal("0.1"):
        return True
    return rate >= 0.25
