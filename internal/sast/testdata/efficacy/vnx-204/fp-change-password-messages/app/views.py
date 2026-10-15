from django.contrib import messages


def change_password(request):
    form = PasswordChangeForm(request.user, request.POST)
    if not form.is_valid():
        messages.error(request, "Invalid password: it must be at least 12 characters")
        return redirect("settings")
    form.save()
    messages.success(request, "Password updated")
    return redirect("settings")


def profile(request, username):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        raise Http404("User not found")
    return render(request, "profile.html", {"profile": user})
