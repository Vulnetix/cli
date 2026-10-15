from django.http import HttpResponseBadRequest, JsonResponse


def upload_resume(request):
    uploaded = request.FILES["resume"]
~>    if not uploaded.name.lower().endswith((".pdf", ".docx")):
        return HttpResponseBadRequest("unsupported file type")
    store(uploaded)
    return JsonResponse({"ok": True})
