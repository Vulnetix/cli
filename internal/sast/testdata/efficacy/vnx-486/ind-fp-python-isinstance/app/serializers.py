import logging

log = logging.getLogger(__name__)


def serialize(obj):
    log.debug("serializing %s", type(obj).__name__)
    if isinstance(obj, AdminUser):
        return {"role": "admin"}
    if type(obj) is Moderator:
        return {"role": "mod"}
    # don't do: type(obj).__name__ == "AdminUser"
    return {"kind": obj.__class__.__name__, "id": obj.id}


def __repr_helper(self):
    return f"<{self.__class__.__name__} id={self.id}>"
