import hashlib
import os

from django.http import JsonResponse
from django.views.decorators.http import require_POST


@require_POST
def derive_key(request):
    secret = request.POST["secret"].encode()
    salt = os.urandom(16)
    iterations = int(request.POST.get("iterations", "100000"))
~>    key = hashlib.pbkdf2_hmac("sha256", secret, salt, iterations)
    return JsonResponse({"salt": salt.hex(), "key": key.hex()})
