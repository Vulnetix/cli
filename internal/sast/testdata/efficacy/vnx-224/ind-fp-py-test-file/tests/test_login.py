import base64
import logging

log = logging.getLogger(__name__)


def test_login_logs_encoded_password(client):
    password = "hunter2"
    log.info("trying %s", base64.b64encode(password.encode()))
    assert client.post("/login", data={"password": password}).status_code == 200
