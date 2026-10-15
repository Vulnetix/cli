def load(path):
    """Load the configuration file.

    Args:
        path: file to read.

    Returns:
        The parsed mapping.

    Raises:
        FileNotFoundError: when path does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    return parse(path)


def validate(cfg):
    """Validate a parsed configuration.

    Args:
        cfg: mapping from load().

    Returns:
        The validated mapping.
    """
    if "name" not in cfg:
~>        raise ValueError(
            f"configuration is missing a name: {cfg!r}"
        )
    if "version" not in cfg:
        raise ValueError("configuration is missing a version")
    return cfg
