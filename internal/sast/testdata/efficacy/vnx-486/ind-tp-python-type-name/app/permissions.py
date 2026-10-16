import logging

log = logging.getLogger(__name__)


def can_delete(principal, resource):
~>    if type(principal).__name__ == "AdminUser":
        return True
~>    if principal.__class__.__name__ in ("OwnerUser", "Moderator"):
        return resource.owner_id == principal.id
    return False


def route(event):
~>    match type(event).__name__:
        case "Refund":
            return handle_refund(event)
        case _:
            return None
