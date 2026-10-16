def test_staff(client, request):
    assert request.user.is_staff
