@bp.route("/change_password", methods=["POST"])
@login_required
def change_password():
    old_password = request.form["old_password"]
    new_password = request.form["new_password"]
    if not current_user.check_password(old_password):
        return "wrong password", 403
    current_user.set_password(new_password)
    db.session.commit()
    return redirect("/profile")


@login_required
def password_change(request):
    if not request.user.check_password(request.POST["old_password"]):
        return redirect("password_change")
    request.user.set_password(request.POST["new_password1"])
    request.user.save()
