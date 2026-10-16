from django.contrib.auth.decorators import login_required
from django.forms.models import model_to_dict
from django.http import JsonResponse


@login_required
def profile(request):
~>    return JsonResponse(model_to_dict(request.user))
