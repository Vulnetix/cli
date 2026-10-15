import hashlib

from django.shortcuts import redirect


def register(request):
    form = SignupForm(request.POST)
    if form.is_valid():
~>        digest = hashlib.md5(form.cleaned_data["password"].encode()).hexdigest()
        User.objects.create(username=form.cleaned_data["username"], pw_hash=digest)
    return redirect("/")
