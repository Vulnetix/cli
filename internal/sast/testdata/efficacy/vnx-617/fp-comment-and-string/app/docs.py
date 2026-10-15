# assert request.user.is_superuser  -- do not do this
HELP = "assert request.user.is_authenticated is stripped by python -O"


def f():
    """
    assert request.user.is_staff
    """
    return HELP
