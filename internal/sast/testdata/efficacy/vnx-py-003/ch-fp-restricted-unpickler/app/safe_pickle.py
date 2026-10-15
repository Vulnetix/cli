import io
import pickle

ALLOWED = {("builtins", "dict"), ("builtins", "list")}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"{module}.{name} is forbidden")


def restricted_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
