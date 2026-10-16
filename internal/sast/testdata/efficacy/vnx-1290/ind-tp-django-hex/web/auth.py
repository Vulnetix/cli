def whoami(request):
    raw = request.COOKIES.get("uid")
~>    ident = bytes.fromhex(raw).decode()
    return Account.objects.get(pk=ident)
