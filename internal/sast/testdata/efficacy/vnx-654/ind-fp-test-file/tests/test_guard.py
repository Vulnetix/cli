def test_local_allowed(client, request):
    if request.remote_addr == "127.0.0.1":
        return True
