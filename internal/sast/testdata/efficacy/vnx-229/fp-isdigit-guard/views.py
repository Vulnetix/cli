def detail(request):
    raw = request.GET.get("id", "")
    if not raw.isdigit():
        return HttpResponseBadRequest()
    pk = int(raw)
    return render(request, "detail.html", {"obj": Thing.objects.get(pk=pk)})
