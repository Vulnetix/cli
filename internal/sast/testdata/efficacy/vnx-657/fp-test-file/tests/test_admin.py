# TODO: add authentication to the fixture server
def test_list_users(client):
    assert client.get("/admin/users").status_code == 200
