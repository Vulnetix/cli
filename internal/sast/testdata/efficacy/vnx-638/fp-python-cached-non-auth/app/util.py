from functools import lru_cache, cached_property


@lru_cache(maxsize=128)
def parse_version(text):
    return tuple(int(x) for x in text.split("."))


@lru_cache
def cancel_reason_labels():
    return {"a": "b"}


class Request:
    @cached_property
    def is_admin(self):
        return self.user.is_superuser
