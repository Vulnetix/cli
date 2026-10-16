import logging

logger = logging.getLogger(__name__)


def test_login_logs(client, caplog):
    response = client.post("/login", {"username": "a", "password": "b"})
    request = response.wsgi_request
    logger.info("login attempt: %s", request.POST)
    print(request.headers)
    assert response.status_code == 200
