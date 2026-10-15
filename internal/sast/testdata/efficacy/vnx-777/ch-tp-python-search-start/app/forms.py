import re


def is_valid_slug(slug):
~>    return re.search(r"^[a-z0-9-]+", slug) is not None
