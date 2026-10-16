from django.contrib.auth.decorators import permission_required


@permission_required("auth.change_user", raise_exception=True)
def change_role(request, uid):
    user = User.objects.get(pk=uid)
    user.role = request.POST["role"]
    user.save()
    return redirect("users")
