from django.http import JsonResponse


~>def delete_account(request, user_id):
    # if not request.user.is_staff:
    #     raise PermissionDenied
    # check_csrf(request)
    # audit.log(request.user, "delete", user_id)
    # from .perms import can_delete
    User.objects.filter(id=user_id).delete()
    return JsonResponse({"ok": True})
