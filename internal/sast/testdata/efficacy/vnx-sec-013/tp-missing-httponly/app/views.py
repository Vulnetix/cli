def login(request):
    response = redirect("/")
    # Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
    response.set_cookie("session_id", token)
    # Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
    response.set_cookie(key="auth_cookie", value=cookie, max_age=3600)
    return response
