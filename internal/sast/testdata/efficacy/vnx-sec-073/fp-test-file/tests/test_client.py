from client import parse_url

def test_parse_url():
    parts = parse_url("https://bob:Hq8Lz3Mv7Rt@files.acme-corp.io/a")
    assert parts.user == "bob"
