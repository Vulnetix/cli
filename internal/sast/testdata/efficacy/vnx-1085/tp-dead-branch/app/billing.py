~>def charge(customer, amount):
    total = amount * 1.1
    # if customer.is_vip:
    #     total = amount
    # discount = lookup_discount(customer.id)
    # total = total - discount
    # log.info("charged %s", total)
    # return total
    return round(total, 2)
