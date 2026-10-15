def test_login(client, user):
    response = client.post("/login", data={"password": "pw"})
    assert response.status_code == 302
    assert user.is_authenticated
    assert False, "should not reach here"
