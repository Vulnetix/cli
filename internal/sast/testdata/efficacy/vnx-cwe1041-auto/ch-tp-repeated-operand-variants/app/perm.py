def can_edit(user, doc):
~>    if user.is_staff or user.is_staff:
        return True
~>    return doc.owner_id == user.id and doc.owner_id == user.id
