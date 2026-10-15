def charge(customer, amount):
    if amount > customer.limit:
~>        breakpoint()
    return customer.charge(amount)


def settle(batch):
    for item in batch:
~>        breakpoint( )
        item.settle()
