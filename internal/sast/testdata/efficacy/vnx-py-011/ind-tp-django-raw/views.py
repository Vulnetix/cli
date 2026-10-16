from django.http import JsonResponse
from .models import User


def lookup(request):
    name = request.GET.get("name")
~>    rows = User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % name)
    return JsonResponse({"users": [u.username for u in rows]})
