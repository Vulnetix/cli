from django.shortcuts import render
from django.views.decorators.cache import cache_control, cache_page

from blog.models import Post


@cache_page(60 * 60)
def post_list(request):
    return render(request, "blog/list.html", {"posts": Post.objects.published()})


@cache_control(public=True, max_age=86400)
def robots_txt(request):
    return render(request, "robots.txt", content_type="text/plain")
