import responses
import requests


@responses.activate
def test_charge():
    responses.add(responses.POST, "http://payments.acme-clearing.com/v1/charge", json={"ok": True})
    assert requests.post("http://payments.acme-clearing.com/v1/charge").json()["ok"]
