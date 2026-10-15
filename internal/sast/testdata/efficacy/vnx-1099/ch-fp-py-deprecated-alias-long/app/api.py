import warnings


class Api:
    def get_user(self, uid):
        return self.http.get(f"/users/{uid}")

    def getUser(self, uid):
        """Deprecated camelCase spelling, kept for 1.x callers."""
        warnings.warn(
            "Api.getUser is deprecated; use Api.get_user",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_user(uid)
