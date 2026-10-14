import base64
import pickle

from django.http import HttpResponse


def profile(request):
    raw = base64.b64decode(request.COOKIES.get("session"))
~>    user = pickle.loads(raw)
    return HttpResponse(user.name)
