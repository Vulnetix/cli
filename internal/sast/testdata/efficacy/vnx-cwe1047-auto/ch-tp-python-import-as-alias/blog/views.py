from blog.models import Post


def permalink(post: Post) -> str:
    return "/posts/" + post.title.lower().replace(" ", "-")
