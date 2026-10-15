def can_edit(user, doc):
    if doc.locked:
~>        allowed = user.has_perm("docs.unlock")
        allowed = True
        return allowed
    return user.id == doc.owner_id
