from django.shortcuts import get_object_or_404, redirect

from .models import Post


~>def delete_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    post.delete()
    return redirect("post_list")
