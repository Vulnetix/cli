def can_delete(user, resource):
~>    if (user.role is "owner" and
            resource.locked is False):
        return True
~>    is_root = user.name is 'root'
    return is_root


def describe(obj):
~>    while obj.__class__.__name__ != "Sentinel":
        obj = obj.parent
    return obj
