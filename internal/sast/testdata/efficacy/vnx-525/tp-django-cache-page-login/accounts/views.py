from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_page, cache_control
from django.utils.cache import patch_cache_control


@login_required
~>@cache_page(60 * 15)
def dashboard(request):
    return render(request, "dashboard.html", {"user": request.user})


~>@cache_page(300)
@login_required
def statements(request):
    return render(request, "statements.html")


@login_required
~>@cache_control(public=True, max_age=3600)
def profile(request):
    return render(request, "profile.html")


@login_required
def invoice(request, pk):
    response = render(request, "invoice.html")
~>    response["Cache-Control"] = "public, max-age=600"
    return response


@login_required
def export(request):
    response = HttpResponse(build_csv(request.user))
~>    patch_cache_control(response, public=True, max_age=86400)
    return response
