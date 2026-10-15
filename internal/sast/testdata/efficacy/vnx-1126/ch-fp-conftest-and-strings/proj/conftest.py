import pytest

_DB = None


@pytest.fixture
def db():
    global _DB
    _DB = make_db()
    yield _DB
