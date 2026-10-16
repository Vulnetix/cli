from django.contrib.auth import login
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def login_view(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
~>        return JsonResponse({"error": "Username does not exist"}, status=401)
    if not user.check_password(password):
        return JsonResponse({"error": "Wrong password"}, status=401)
    login(request, user)
    return JsonResponse({"ok": True})
