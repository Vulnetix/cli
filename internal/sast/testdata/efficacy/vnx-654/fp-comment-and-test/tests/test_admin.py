def fake_gate(request):
    if request.remote_addr == "127.0.0.1":
        return True
    return False
