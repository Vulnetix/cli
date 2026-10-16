from django.core.exceptions import PermissionDenied
from django.http import JsonResponse

from .permissions import require_staff


def order_admin(request, order_id):
    data = {"order": order_id}
    try:
        require_staff(request.user)
        data["internal_notes"] = load_notes(order_id)
~>    except PermissionDenied:
        pass
    return JsonResponse(data)
