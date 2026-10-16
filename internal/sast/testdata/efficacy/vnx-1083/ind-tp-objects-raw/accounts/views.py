from .models import User


def search(request):
    term = request.GET.get("q", "")
~>    return User.objects.raw("SELECT * FROM users WHERE name LIKE %s", [term])
