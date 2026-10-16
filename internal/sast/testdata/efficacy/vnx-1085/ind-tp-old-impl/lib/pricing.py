import math


~>def price(item, qty):
    base = item.cost * qty
    # total = 0
    # for line in item.lines:
    #     total += line.amount
    # import decimal
    # return decimal.Decimal(total)
    return math.ceil(base)
