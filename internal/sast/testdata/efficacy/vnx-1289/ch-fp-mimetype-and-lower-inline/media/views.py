from django.http import HttpResponseBadRequest, HttpResponse


def upload(request):
    doc = request.FILES["doc"]
    if doc.name.lower().endswith((".php", ".exe")):
        return HttpResponseBadRequest("not allowed")
    if doc.content_type == "text/html":
        return HttpResponseBadRequest("not allowed")
    help_text = "Files ending in .php or .exe are rejected"
    return HttpResponse(help_text)
