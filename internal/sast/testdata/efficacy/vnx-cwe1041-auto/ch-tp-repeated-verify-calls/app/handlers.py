def delete_post(request, post_id):
    verify_csrf_token(request)
~>    verify_csrf_token(request)
    post = Post.objects.get(pk=post_id)
    post.delete()
