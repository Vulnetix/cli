import hmac
from django.http import HttpResponseForbidden


def api_login(request):
    supplied = request.POST.get("digest")
    user = User.objects.get(username=request.POST["username"])
~>    if not hmac.compare_digest(user.profile.password_hash, supplied):
        return HttpResponseForbidden()
    return start_session(request, user)
