import uuid


def order_detail(request):
    raw = request.GET.get("id")
    note = request.POST["note"]
~>    order = Order.objects.get(pk=int(raw))
~>    ref = uuid.UUID(request.GET["ref"])
    return render(request, "order.html", {"order": order, "note": note, "ref": ref})
