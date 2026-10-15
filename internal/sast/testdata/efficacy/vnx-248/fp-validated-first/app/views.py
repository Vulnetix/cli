def items(request):
    raw = request.GET.get("page", "1")
    if not raw.isdigit():
        return HttpResponseBadRequest()
    page = int(raw)
    count = int(settings.PAGE_SIZE)
    return render(request, "items.html", {"page": page})
