from flask import request, session, abort

@app.before_request
def gate():
~>    if request.path.startswith("/admin") and not session.get("is_admin"):
        abort(403)
