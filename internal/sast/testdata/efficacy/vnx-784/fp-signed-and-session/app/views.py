def admin_panel(request):
    role = request.get_signed_cookie("role", default=None, salt="roles")
    if role == "admin":
        return render_admin(request)
    if request.session.get("role") == "admin":
        return render_admin(request)
    if request.user.is_staff:
        return render_staff(request)
    return forbidden()


def bottle_admin(request, KEY):
    if request.get_cookie("role", secret=KEY) == "admin":
        return "ok"
