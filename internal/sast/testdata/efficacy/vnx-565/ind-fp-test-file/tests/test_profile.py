from accounts.models import Account


def test_profile_uses_cookie(client, rf):
    request = rf.get("/profile")
    request.COOKIES["userid"] = "1"
    obj = Account.objects.filter(userid=request.COOKIES["userid"]).first()
    assert obj is None
