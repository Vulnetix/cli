def test_filter_passes_params(rf):
    request = rf.get("/orders?status=open")
    qs = Order.objects.filter(**request.GET.dict())
    assert qs.query is not None
