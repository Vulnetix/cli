from urllib.parse import quote


def export(request):
    name = request.GET.get("name", "report")
    response = HttpResponse(build_csv(), content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(name)
    response["X-Page"] = str(int(request.GET.get("page", 1)))
    return response
