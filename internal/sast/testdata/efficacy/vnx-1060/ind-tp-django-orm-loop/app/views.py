from .models import Customer, Order


def summarise(customer_ids):
    totals = {}
    for cid in customer_ids:
~>        customer = Customer.objects.get(pk=cid)
        totals[cid] = customer.balance
    return totals
