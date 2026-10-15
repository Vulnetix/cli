from django.contrib.auth.decorators import login_required
from django.forms.models import model_to_dict
from django.http import JsonResponse


@login_required
def me(request):
~>    return JsonResponse(model_to_dict(request.user))


def profile(request, pk):
    user = request.user
~>    data = model_to_dict(user)
    return JsonResponse(data)
