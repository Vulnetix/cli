from rest_framework import authentication, exceptions


class ApiKeyAuthentication(authentication.BaseAuthentication):
    keyword = "Api-Key"

    def authenticate(self, request):
        key = request.headers.get("X-Api-Key")
        if not key:
            return None
        return self.lookup(key)

    def authenticate_header(self, request):
        return self.keyword

    def is_token_expired(self, token):
        return True

    def check_token_expiry(self, token):
        return True
