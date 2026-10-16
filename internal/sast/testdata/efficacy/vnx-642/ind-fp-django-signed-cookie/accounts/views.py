from django.http import JsonResponse


def remember_staff(request):
    response = JsonResponse({"ok": True})
    response.set_signed_cookie("is_admin", "1" if request.user.is_staff else "0", salt="staff-flag", max_age=3600)
    return response


def show_flag(request):
    flag = request.get_signed_cookie("is_admin", default="0", salt="staff-flag")
    return JsonResponse({"staff": flag})
