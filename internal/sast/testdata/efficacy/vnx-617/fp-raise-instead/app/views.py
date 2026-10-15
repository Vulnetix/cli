from django.core.exceptions import PermissionDenied


def delete_user(request, user_id):
    if not request.user.is_superuser:
        raise PermissionDenied
    amount = request.POST.get("amount", "")
    if not amount.isdigit():
        raise ValueError("amount")
    return do_delete(user_id, amount)
