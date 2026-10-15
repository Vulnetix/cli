import os
from django.shortcuts import render

POSTS = {"intro", "release-notes"}


def blog(request):
    name = request.POST["blog"]
    safe = os.path.basename(name)
    target = os.path.join("/srv/posts", safe + ".md")
    with open(target, "r") as fh:
        body = fh.read()
    slug = request.GET["slug"]
    if slug not in POSTS:
        slug = "intro"
    other = os.path.join("/srv/posts", slug + ".md")
    with open(other) as fh:
        body += fh.read()
    return render(request, "blog.html", {"body": body})
