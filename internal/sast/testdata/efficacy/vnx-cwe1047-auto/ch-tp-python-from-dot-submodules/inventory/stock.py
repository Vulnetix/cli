from . import pricing

LOW_WATER = 5


def reorder_cost(item):
    return pricing.unit_price(item) * LOW_WATER
