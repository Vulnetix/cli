from flask import abort, request


def purge_cache():
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.cookies.get("role") != "admin":
        abort(403)
    cache.clear()
    return "ok"


def stats():
    staff = request.headers.get("X-Staff")
~>    if not staff:
        abort(401)
    return compute_stats()
