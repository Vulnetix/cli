import pytest

from app import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config["RATELIMIT_ENABLED"] = False
    return app
