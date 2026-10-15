from app import create_app


def test_spoofed_header_is_ignored():
    client = create_app().test_client()
    resp = client.get(
        "/whoami",
        headers={"X-Forwarded-For": "203.0.113.9"},
        environ_base={"REMOTE_ADDR": "10.0.0.1"},
    )
    assert resp.json["ip"] == "10.0.0.1"
