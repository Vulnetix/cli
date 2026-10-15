from django.contrib.auth.models import User
from django.http import JsonResponse


def lookup(request):
    username = request.GET["u"]
~>    users = User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % username)
    return JsonResponse({"ids": [u.id for u in users]})
