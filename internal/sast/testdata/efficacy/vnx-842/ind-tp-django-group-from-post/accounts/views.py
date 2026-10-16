from django.contrib.auth.models import Group
from django.http import JsonResponse


def join_team(request):
    user = request.user
~>    user.groups.add(Group.objects.get(name=request.POST["group"]))
    return JsonResponse({"ok": True})
