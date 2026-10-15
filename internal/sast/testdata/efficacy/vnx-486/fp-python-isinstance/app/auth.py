def authorize(principal):
    if isinstance(principal, AdminUser):
        return True
    if type(principal) is ServiceAccount:
        return True
    label = type(principal).__name__
    logger.info("principal %s", principal.__class__.__name__)
    return False
