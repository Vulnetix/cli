from django.shortcuts import render

from .services import find_users


def search(request):
    """Search users.

    The old implementation was:

    >>> User.objects.raw("SELECT * FROM auth_user WHERE name = %s", [name])
    >>> sqlite3.connect("users.db")
    """
    return render(request, "search.html", {"users": find_users(request.GET.get("q", ""))})
