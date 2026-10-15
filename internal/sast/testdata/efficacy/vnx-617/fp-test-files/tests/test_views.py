def test_delete(client):
    response = client.post("/delete")
    assert response.status_code == 403
    assert request.user.is_superuser is False
