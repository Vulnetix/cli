from .models import Customer


def customer_names(ids):
~>    return {cid: Customer.objects.get(pk=cid).name for cid in ids}
