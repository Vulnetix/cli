from django.http import HttpResponse, JsonResponse

from .models import Order


def cancel(request, pk):
    try:
        Order.objects.get(pk=pk).cancel()
    except Order.DoesNotExist:
~>        return HttpResponse("Order not found")
    except PermissionError:
~>        return JsonResponse({'message': 'Permission denied'}, safe=False)
    return JsonResponse({"cancelled": pk})
