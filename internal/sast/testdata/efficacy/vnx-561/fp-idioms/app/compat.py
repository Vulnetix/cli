if False:  # pragma: no cover - type checking only
    from typing import List


def empty_generator():
    return
    yield


def never():
    if False:
        yield None
    if TYPE_CHECKING:
        pass
    while True:
        work()
