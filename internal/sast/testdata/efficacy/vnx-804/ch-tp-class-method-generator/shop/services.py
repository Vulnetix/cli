import random
import string

from django.core.cache import cache


class CaptchaService:
    length = 6

    def generate(self, key):
~>        code = "".join(random.choices(string.ascii_uppercase + string.digits, k=self.length))
        cache.set(f"cap:{key}", code, timeout=300)
        return code

    def check(self, key, value):
        expected = cache.get(f"cap:{key}")
        return expected is not None and expected == value.upper()
