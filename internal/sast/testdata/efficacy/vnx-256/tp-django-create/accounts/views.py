def signup(request):
~>    User.objects.create(username=request.POST["username"], password=request.POST["password"])
    pw = request.POST.get("password")
~>    Account(email=request.POST["email"], password=pw).save()
    return redirect("login")
