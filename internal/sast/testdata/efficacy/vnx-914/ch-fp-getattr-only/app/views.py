from flask import request


def sort_items(items):
    order = request.args.get("order", "name")
    attr = getattr(Item, order, Item.name)
    setattr(g, "sort_key", attr)
    return sorted(items, key=lambda i: getattr(i, "name"))
