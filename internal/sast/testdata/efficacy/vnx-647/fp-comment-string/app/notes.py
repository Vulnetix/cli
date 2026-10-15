# Bad: if request.path.startswith("/admin") and not session.get("is_admin"): abort(403)
DOC = 'if request.path.startswith("/admin"): abort(403)  # bypassed by //admin'
