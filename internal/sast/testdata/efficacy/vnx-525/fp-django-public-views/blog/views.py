from django.views.decorators.cache import cache_page, cache_control
from django.contrib.auth.decorators import login_required


@cache_page(60 * 15)
def post_list(request):
    return render(request, "posts.html")


@cache_control(public=True, max_age=600)
def about(request):
    return render(request, "about.html")


@login_required
@cache_control(private=True, max_age=60)
def drafts(request):
    return render(request, "drafts.html")


@login_required
def settings_page(request):
    return render(request, "settings.html")
