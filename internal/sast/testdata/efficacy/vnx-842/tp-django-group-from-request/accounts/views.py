from django.contrib.auth.models import Group, User
from django.http import JsonResponse


def register(request):
    user = User.objects.create_user(
        request.POST["username"], password=request.POST["password"]
    )
~>    user.groups.add(Group.objects.get(name=request.POST["group"]))
    return JsonResponse({"id": user.id})
