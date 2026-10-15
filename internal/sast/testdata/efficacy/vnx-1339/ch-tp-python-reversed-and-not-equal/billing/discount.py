def apply_discount(price, rate):
~>    if 0.1 == rate:
        return price * 0.9
~>    while rate != 0.3:
        rate += 0.1
    return price
