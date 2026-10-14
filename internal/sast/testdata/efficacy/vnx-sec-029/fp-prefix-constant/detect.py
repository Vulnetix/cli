PYPI_PREFIX = "pypi-AgEIcHlwaS5vcmc"
TEST_PYPI_PREFIX = "pypi-AgENdGVzdC5weXBpLm9yZw"


def is_pypi_token(value: str) -> bool:
    return value.startswith((PYPI_PREFIX, TEST_PYPI_PREFIX))
