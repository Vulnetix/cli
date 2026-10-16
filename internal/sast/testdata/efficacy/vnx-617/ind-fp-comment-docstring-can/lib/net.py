def check(host):
    """Example: assert request.user.is_superuser fails under python -O."""
    # assert request.user.is_authenticated
    assert can_connect(host)
    return True
