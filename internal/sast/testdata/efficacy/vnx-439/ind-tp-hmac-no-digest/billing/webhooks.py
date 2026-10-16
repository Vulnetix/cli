import hmac

from django.conf import settings
from django.http import HttpResponseForbidden


def verify(request):
    sent = request.headers.get("X-Signature", "")
~>    expected = hmac.new(settings.WEBHOOK_SECRET.encode(), request.body).hexdigest()
    if not hmac.compare_digest(sent, expected):
        return HttpResponseForbidden()
    return None
