def test_change_password(client, user):
    new_password = "correct horse battery staple"
    user.set_password(new_password)
    resp = client.post("/change_password", data={"new_password": new_password})
    assert resp.status_code == 302
