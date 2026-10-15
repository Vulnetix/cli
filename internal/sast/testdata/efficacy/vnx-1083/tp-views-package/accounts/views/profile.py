from django.db import connections
from django.shortcuts import render


def profile(request, user_id):
~>    with connections["replica"].cursor() as c:
        c.execute("SELECT * FROM accounts_profile WHERE user_id = %s", [user_id])
        row = c.fetchone()
    return render(request, "profile.html", {"row": row})
