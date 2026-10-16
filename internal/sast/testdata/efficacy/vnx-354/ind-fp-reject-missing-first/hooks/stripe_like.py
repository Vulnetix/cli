import hashlib
import hmac

from django.http import HttpResponse, HttpResponseForbidden


def receive(request):
    signature = request.headers.get("X-Signature")
    if not signature:
        return HttpResponseForbidden("missing signature")
    expected = hmac.new(KEY, request.body, hashlib.sha256).hexdigest()
    if signature and not hmac.compare_digest(signature, expected):
        return HttpResponseForbidden("bad signature")
    process(request.body)
    return HttpResponse(status=204)
