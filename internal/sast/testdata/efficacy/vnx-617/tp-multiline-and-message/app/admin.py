def promote(request):
~>    assert (
        request.user.is_staff
        and request.method == "POST"
    ), "forbidden"
    return render(request, "ok.html")
