from django.views.decorators.cache import cache_page
from django.contrib.auth.decorators import login_required


@cache_page(60 * 60)
def post_list(request):
    return render(request, "posts.html", {"posts": Post.objects.all()})


@login_required
def settings(request):
    response = render(request, "settings.html")
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response
