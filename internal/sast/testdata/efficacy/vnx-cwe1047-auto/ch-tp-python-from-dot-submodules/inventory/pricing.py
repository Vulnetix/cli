~>from . import warehouse

BASE = {"bolt": 3, "nut": 1}


def unit_price(item):
    if warehouse.needs_reorder(item, 0):
        return BASE.get(item, 0) * 2
    return BASE.get(item, 0)
