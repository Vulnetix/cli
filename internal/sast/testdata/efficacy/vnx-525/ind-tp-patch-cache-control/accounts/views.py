from django.http import JsonResponse
from django.utils.cache import patch_cache_control


def settings_view(request):
    data = {"email": request.user.email, "mfa": request.user.mfa_enabled}
    response = JsonResponse(data)
~>    patch_cache_control(response, public=True, max_age=1800)
    return response
