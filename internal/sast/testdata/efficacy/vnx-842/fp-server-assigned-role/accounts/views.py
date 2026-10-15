from django.contrib.auth.models import Group, User


def register(request):
    user = User.objects.create_user(request.POST["username"], password=request.POST["password"])
    user.groups.add(Group.objects.get(name="customers"))
    user.role = "member"
    user.is_staff = False
    user.save()
    return user
