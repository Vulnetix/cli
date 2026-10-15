def load(config, strict=False):
    """Load settings.

    Args:
        config: mapping with the keys below.
            config.timeout: seconds.
            retries: how many attempts.
        strict: raise on unknown keys.
    """
    return _parse(config, strict)
