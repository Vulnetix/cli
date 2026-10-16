from django.contrib.auth.models import User


def register(request):
    name = request.POST["username"]
    pw1 = request.POST["password1"]
~>    pw2 = request.POST.get("password2", "")
    User.objects.create_user(username=name, password=pw1)
