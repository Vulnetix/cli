def authenticate(request):
    try:
        user = verify_jwt(request.headers["Authorization"])
    except jwt.InvalidTokenError:
        raise PermissionDenied("bad token")
    request.user = user
    return True
