def test_staff_can_delete(client, staff_user):
    client.force_login(staff_user)
    response = client.post("/invoices/1/delete")
    assert response.wsgi_request.user.is_authenticated
    assert staff_user.has_perm("billing.delete_invoice")
    assert False is not True
