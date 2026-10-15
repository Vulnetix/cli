from django.http import HttpResponseBadRequest


def upload(request):
    uploaded = request.FILES["file"]
~>    if uploaded.name.endswith((".php", ".phtml", ".exe")):
        return HttpResponseBadRequest("file type not allowed")
    save(uploaded)
