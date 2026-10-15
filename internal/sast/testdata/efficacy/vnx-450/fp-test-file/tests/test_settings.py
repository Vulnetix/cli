import os

RUN_SLOW = bool(os.environ.get("RUN_SLOW"))


def test_debug_default():
    assert os.environ.get("APP_DEBUG", False) is False
