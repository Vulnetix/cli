import base64
import pickle

from django.http import JsonResponse


def resume(request):
    raw = request.headers.get("X-Wizard-State", "")
~>    state = pickle.loads(base64.urlsafe_b64decode(raw))
    return JsonResponse({"step": state["step"], "owner": state["owner"]})
