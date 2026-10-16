from django.http import JsonResponse

from .models import Warehouse


def warehouse_detail(request, code):
    try:
        wh = Warehouse.objects.get(code=code)
    except Warehouse.DoesNotExist:
        return JsonResponse(
            {"error": "warehouse not found"},
            status=404,
        )
    except OSError:
        return JsonResponse({"error": "storage unavailable"}, status=503)
    return JsonResponse(wh.as_dict())
