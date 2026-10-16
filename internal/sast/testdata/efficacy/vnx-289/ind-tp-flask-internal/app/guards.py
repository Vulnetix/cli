from flask import abort, request, session


def install(app):
    @app.before_request
    def block_internal():
~>        if request.path == "/internal/metrics" and not session.get("staff"):
            abort(403)
