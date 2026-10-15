from flask import request


def preferences():
    admin_email = request.form["admin_email"]
    theme = request.cookies.get("theme", "light")
    contact = request.args.get("administrator_contact")
    if request.args.get("verbose"):
        theme = "debug-" + theme
    admins = request.headers.get("X-Request-Id")
    return admin_email, theme, contact, admins
