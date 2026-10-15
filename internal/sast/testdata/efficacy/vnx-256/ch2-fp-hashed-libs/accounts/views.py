from django.contrib.auth.hashers import make_password


def register(request):
    pw = make_password(request.POST.get("password"))
    Account.objects.create(username=request.POST["username"], password=pw)
    user = User.objects.create_user(request.POST["username"], password=request.POST["password"])
    user.set_password(request.POST["password"])
