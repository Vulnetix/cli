from flask import request, session, abort


def a():
    if session.get('role') == 'admin':
        return go()
    if request.user.is_staff:
        return go()
    if request.args.get('role') is None:
        abort(400)
    user = User(name=request.form['name'], role='member')
    return user
