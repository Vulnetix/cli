from flask import request, abort


def delete_user():
~>    if request.form.get('is_admin') == "1":
        return do_delete()
    abort(403)


def panel():
    role = request.args.get('role')
~>    if role == 'admin':
        return render()
    abort(403)
