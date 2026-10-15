def check(request):
    assert request.user.is_authenticated
