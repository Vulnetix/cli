def can_delete(user):
~>    if type(user).__name__ != "Guest":
        return True
~>    if user.__class__.__qualname__ == "Staff.Admin":
        return True
    kind = type(user).__name__
~>    return kind in {"Owner", "Root"}
