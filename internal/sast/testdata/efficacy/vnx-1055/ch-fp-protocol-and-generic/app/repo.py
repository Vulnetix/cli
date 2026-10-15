from typing import Generic, Protocol, TypeVar

T = TypeVar("T")


class Readable(Protocol):
    def read(self) -> bytes: ...


class Closeable(Protocol):
    def close(self) -> None: ...


class Box(Generic[T]):
    def __init__(self, item: T):
        self.item = item


class Handle(Readable, Closeable):
    def read(self) -> bytes:
        return b""

    def close(self) -> None:
        pass


class IntBox(Box[int], Readable):
    def read(self) -> bytes:
        return bytes(self.item)
