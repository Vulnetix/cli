from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def sign_in(request):
    user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
    if user is None:
        return JsonResponse({"error": "bad credentials"}, status=401)
    login(request, user)
    response = JsonResponse({"ok": True})
~>    response.set_cookie("is_admin", "1" if user.is_staff else "0", max_age=3600, httponly=True)
    return response
