def remove_first(users, name):
    for u in users:
        if u.name == name:
            users.remove(u)
            break
    return users


def take(items, wanted):
    for item in items:
        if item.id == wanted:
            items.remove(item)

            return item
    return None
