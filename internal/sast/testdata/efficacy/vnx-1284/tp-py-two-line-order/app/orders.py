from django.http import JsonResponse


def add_to_order(request, product):
    qty = int(request.POST.get("quantity", 1))
    note = request.POST.get("note", "")
~>    total = product.price * qty
~>    OrderLine.objects.create(product=product, quantity=qty, note=note)
    return JsonResponse({"total": str(total)})


def redeem(request, user):
    points = request.json.get("points")
~>    user.points = user.points - points
    user.save()
