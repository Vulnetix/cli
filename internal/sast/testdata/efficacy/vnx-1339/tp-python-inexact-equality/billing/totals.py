def settle(items):
    total = sum(i.price for i in items)
~>    if total == 0.3:
        return "promo"
    balance = total
~>    while balance != 0.1:
        balance -= 0.1
    ratio = balance / total
~>    if 0.7 == ratio:
        return "seventy"
~>    return total*0.1==0.03
