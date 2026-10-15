from flask import abort, request

TRUSTED = {"10.0.0.5", "10.0.0.6"}


@app.route("/admin/flush")
def flush():
~>    if request.headers.get("X-Real-IP") != "10.0.0.5":
        abort(403)
    return do_flush()


@app.route("/admin/stats")
def stats():
    client = request.headers.get('X-Forwarded-For', '')
~>    if client in TRUSTED:
        return render_stats()
    abort(403)
