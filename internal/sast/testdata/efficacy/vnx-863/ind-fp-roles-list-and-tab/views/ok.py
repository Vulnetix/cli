from flask import request


def page(user):
    if "admin" in user.roles:
        return admin_page()
    if request.args.get("tab") == "admin":
        return render_tab("admin")
    return render_tab("home")
