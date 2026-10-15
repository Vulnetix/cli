def login(request):
    target = request.GET.get("next", "/")
~>    # TODO: validate the redirect target before use
    return redirect(target)
