from urllib.parse import quote

from django.http import FileResponse


def download(request, doc_id):
    name = request.GET.get("name", "document")
    doc = load_document(request.user, doc_id)
    response = FileResponse(doc.open("rb"), content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(name)
    response["X-Frame-Options"] = "DENY"
    return response
