def make_client(url, verify=False):
    return Client(url, verify=verify)


def test_fetch():
    assert make_client("https://localhost:8443").get("/") is not None
