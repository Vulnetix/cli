def sign_up(request):
    form = SignupForm(request.POST)
    user = form.save()
~>    user.is_superuser = True
    user.save()
    return redirect("home")
