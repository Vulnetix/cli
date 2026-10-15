from django.http import JsonResponse
from .repositories.orders import orders_for
from .models import Order

def report(request):
    rows = orders_for(request.user.id)
    recent = Order.objects.filter(user=request.user).order_by("-created")[:5]
    return JsonResponse({"rows": rows, "recent": list(recent.values())})
