def page(request):
    value = fetch(request)
    items = [v.id for v in value]
    value = fetch_more(request)
    label = compute(request)
    print(f"label={label}")
    label = compute_again(request)
    handler = make()
    cb = lambda: handler.run()
    handler = make_other()
    return items, value, label, cb, handler
