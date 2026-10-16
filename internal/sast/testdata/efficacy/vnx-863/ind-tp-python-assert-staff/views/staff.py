def dashboard(request):
~>    assert request.user.is_staff, "staff only"
    return render(request, "dash.html")
