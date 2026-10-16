def view(resp, token):
    resp.set_cookie("session_id", token, httponly=True, secure=True)
    resp.set_cookie("csrftoken", "x")
    resp.set_cookie("language", "en")
    resp.delete_cookie("session_id")
    return resp
