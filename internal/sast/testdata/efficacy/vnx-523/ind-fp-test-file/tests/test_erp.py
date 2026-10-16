import requests
import responses


@responses.activate
def test_fetch_orders():
    responses.add(responses.GET, "http://orders.acme-corp.com/api/orders", json=[])
    resp = requests.get("http://orders.acme-corp.com/api/orders", auth=("u", "p"))
    assert resp.json() == []
