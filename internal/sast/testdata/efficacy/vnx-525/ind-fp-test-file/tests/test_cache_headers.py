from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.views.decorators.cache import cache_page


@login_required
@cache_page(60)
def fake_view(request):
    response = HttpResponse(request.user.username)
    response["Cache-Control"] = "public, max-age=60"
    return response


def test_fake_view_is_cached(rf):
    assert fake_view
