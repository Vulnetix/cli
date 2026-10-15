from django.http import HttpResponse


def help_page(request):
    # Do not call connection.cursor() here; use shop.repository instead.
    text = "Views must not call connection.cursor() or sqlite3.connect() directly."
    return HttpResponse(text)
