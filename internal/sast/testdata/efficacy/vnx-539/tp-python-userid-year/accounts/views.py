def login_view(request):
    response = redirect("/home")
~>    response.set_cookie('userid', user.userid, max_age=31449600, secure=False)
    return response
