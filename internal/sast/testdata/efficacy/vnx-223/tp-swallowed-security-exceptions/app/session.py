from django.core.exceptions import PermissionDenied, SuspiciousOperation
from itsdangerous import BadSignature, URLSafeSerializer
from jwt import InvalidTokenError

serializer = URLSafeSerializer(SECRET)


def load_cart(cookie):
    cart = {}
    try:
        cart = serializer.loads(cookie)
~>    except BadSignature:
        pass
    return cart


def handle(request):
    try:
        enforce(request)
~>    except (PermissionDenied, SuspiciousOperation):
        ...
    return render(request)


def refresh(token):
    try:
        rotate(token)
~>    except InvalidTokenError:
        pass
