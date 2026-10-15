@login_required
@cache_page(60)
def fake_view(request):
    return HttpResponse("x")
