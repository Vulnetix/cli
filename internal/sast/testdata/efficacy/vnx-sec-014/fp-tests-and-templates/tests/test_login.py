def test_login(client):
    password = "Corr3ct-H0rse"
    assert client.login("alice", password)
