import base64
import cPickle as pickle_mod
import dill

from django.http import JsonResponse


def restore_cart(request):
    raw = base64.b64decode(request.POST["cart"])
    cart = pickle_mod.loads(raw)
    return JsonResponse({"items": len(cart)})


def restore_job(request):
    blob = request.body
    job = dill.loads(blob)
    return JsonResponse({"id": job.id})
