from django.http import JsonResponse


def login_view(request):
    token = make_token(request.POST["username"])
    resp = JsonResponse({"ok": True})
~>    resp.set_cookie("session_id", token, max_age=3600, secure=True)
    return resp
