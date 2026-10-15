from django.http import JsonResponse


def save_preferences(request):
    if request.method == "POST":
~>        request.session.update(request.POST)
    return JsonResponse({"ok": True})
