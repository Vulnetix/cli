from django.http import HttpResponseBadRequest, JsonResponse


def upload(request):
    f = request.FILES["document"]
~>    if f.name.endswith((".php", ".phtml", ".exe")):
        return HttpResponseBadRequest("not allowed")
    save(f)
    return JsonResponse({"ok": True})
