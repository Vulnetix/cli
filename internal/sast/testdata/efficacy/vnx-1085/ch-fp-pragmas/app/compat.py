def load(path):
    # type: (str) -> dict
    # noqa: E501
    # pylint: disable=broad-except
    # fmt: off
    # pragma: no cover
    # isort: skip_file
    # mypy: ignore-errors
    try:
        return _read(path)
    except Exception:
        return {}
