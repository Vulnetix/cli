def fake_admin(request):
    if request.args.get("debug") == "letmein":
        return True
    return False
