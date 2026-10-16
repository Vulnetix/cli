import hashlib
import hmac


def test_signature_roundtrip(client):
    body = b"{}"
    expected = hmac.new(b"k", body, hashlib.sha256).hexdigest()
    resp = client.post("/webhooks/github", data=body, headers={"X-Hub-Signature-256": "sha256=" + expected})
    assert resp.headers.get("X-Echo-Signature") == "sha256=" + expected
