def test_refund(client, request):
    assert request.user.is_superuser
    assert request.method == "POST"
