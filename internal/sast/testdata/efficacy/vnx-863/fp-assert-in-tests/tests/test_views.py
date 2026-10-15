def test_staff_page(client, staff):
    response = client.get("/staff/")
    assert response.context["user"].is_staff
    assert staff.has_role("admin")
    assert isinstance(response.content, bytes)
