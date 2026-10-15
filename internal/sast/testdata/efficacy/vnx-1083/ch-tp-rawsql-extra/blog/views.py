from django.db.models.expressions import RawSQL
from django.shortcuts import render

from .models import Post


def popular(request):
~>    posts = Post.objects.annotate(score=RawSQL("SELECT count(*) FROM likes WHERE post_id = blog_post.id", ()))
~>    recent = Post.objects.extra(where=["created > now() - interval '7 days'"])
    return render(request, "blog/popular.html", {"posts": posts, "recent": recent})
