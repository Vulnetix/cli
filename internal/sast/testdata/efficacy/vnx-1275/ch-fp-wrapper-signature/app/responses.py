from django.http import HttpResponse


class TrackedResponse(HttpResponse):
    def set_cookie(self, key, value="", max_age=None, expires=None, path="/",
                   domain=None, secure=False, httponly=False,
                   samesite=None):
        self.tracked.append(key)
        return super().set_cookie(key, value, max_age=max_age, expires=expires, path=path,
                                  domain=domain, secure=secure, httponly=httponly,
                                  samesite=samesite)
