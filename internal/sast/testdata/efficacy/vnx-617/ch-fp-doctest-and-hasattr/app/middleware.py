def attach_user(request, user):
    """Attach the user to the request.

    >>> assert request.user.is_authenticated
    """
    assert hasattr(request, "META")
    assert request is not None
    request.user = user
    return request
