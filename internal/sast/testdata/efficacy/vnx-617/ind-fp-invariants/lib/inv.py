def process(request, items):
    assert isinstance(request, object)
    assert items is not None
    assert len(items) > 0
    return items
