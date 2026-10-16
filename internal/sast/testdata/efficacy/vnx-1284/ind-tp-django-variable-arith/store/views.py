def order_total(request, item):
    qty = int(request.POST.get("quantity", 1))
~>    total = item.price * qty
    return total
