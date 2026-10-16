def total(items):
    t = 0
~>    # for item in items:
    #     t += item.price
    #     print(t)
    return sum(i.price for i in items)
