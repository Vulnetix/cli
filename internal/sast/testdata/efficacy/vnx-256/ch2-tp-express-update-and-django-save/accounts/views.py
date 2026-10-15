from django.http import JsonResponse


def register(request):
    pw = request.POST.get("password")
~>    profile = Account(username=request.POST.get("username"), password=pw)
    profile.save()
    return JsonResponse({"ok": True})
