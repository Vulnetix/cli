from django.shortcuts import get_object_or_404


def order_detail(request, pk):
    order = get_object_or_404(Order, pk=request.GET["id"], customer=request.user)
    return render(request, "order.html", {"order": order})
