from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from app.models import Event

if False:
    from app.models import Account  # noqa: F401  (type-only import)


def empty_events() -> "Iterator[Event]":
    return
    yield


def never_yields():
    if False:
        yield None


def first_ok(items):
    for item in items:
        try:
            return item.load()
        except IOError:
            continue
        finally:
            item.close()
    return None


def total(values):
    return (
        sum(values)
        + len(values)
    )
