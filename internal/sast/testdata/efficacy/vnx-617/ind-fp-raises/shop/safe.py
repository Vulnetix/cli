from django.core.exceptions import PermissionDenied


def refund(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    if not request.POST.get("amount", "").isdigit():
        raise ValueError("amount")
    return "ok"
