def test_filter(rf):
    request = rf.get("/search", {"name": "a"})
    assert User.objects.filter(**request.GET.dict()).count() == 0
