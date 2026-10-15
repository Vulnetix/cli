from . import stock


def needs_reorder(item, qty):
    return qty < stock.LOW_WATER
