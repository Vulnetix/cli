from django.http import JsonResponse


def dashboard_prefs(request):
    raw = request.COOKIES.get("dashboard_prefs", "{}")
~>    prefs = eval(raw)
    columns = prefs.get("columns", ["name", "status"])
    return JsonResponse({"columns": columns})
