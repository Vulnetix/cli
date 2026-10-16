PYPI_TOKEN_PREFIX = "pypi-AgEIcHlwaS5vcmc"

def looks_like_pypi(s):
    return s.startswith(PYPI_TOKEN_PREFIX)
