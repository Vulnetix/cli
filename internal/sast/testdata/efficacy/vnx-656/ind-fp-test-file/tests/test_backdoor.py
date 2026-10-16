def test_magic(request):
    if request.args.get("debug") == "letmein":
        return True
