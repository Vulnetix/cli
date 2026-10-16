import os

import pytest

DEBUG = bool(os.environ.get("TEST_DEBUG"))
SKIP_SLOW = os.environ.get("SKIP_SLOW", False)


@pytest.fixture
def verbose():
    return bool(os.getenv("VERBOSE"))
