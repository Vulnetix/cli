from django.contrib.auth.models import Group
from django.shortcuts import redirect


def join_team(request):
    if request.method == "POST":
        group = Group.objects.get(name=request.POST["group"])
~>        request.user.groups.add(group)
    return redirect("home")
