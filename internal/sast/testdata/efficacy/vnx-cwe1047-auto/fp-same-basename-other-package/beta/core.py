from .util import slugify


def title(text):
    return slugify(text).title()
