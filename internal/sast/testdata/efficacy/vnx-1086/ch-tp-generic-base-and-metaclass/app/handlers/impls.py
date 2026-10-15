from typing import Generic, TypeVar
from .base import Handler

T = TypeVar('T')


class H0(Handler, Generic[T]):
    kind = 0


class H1(Handler, Generic[T]):
    kind = 1


class H2(Handler, Generic[T]):
    kind = 2


class H3(Handler, Generic[T]):
    kind = 3


class H4(Handler, Generic[T]):
    kind = 4


class H5(Handler, Generic[T]):
    kind = 5


class H6(Handler, Generic[T]):
    kind = 6


class H7(Handler, Generic[T]):
    kind = 7


class H8(Handler, Generic[T]):
    kind = 8


class H9(Handler, Generic[T]):
    kind = 9


class H10(Handler, Generic[T]):
    kind = 10


class H11(Handler, Generic[T]):
    kind = 11


class J0(
    Handler,
    metaclass=type,
):
    kind = 0


class J1(
    Handler,
    metaclass=type,
):
    kind = 1


class J2(
    Handler,
    metaclass=type,
):
    kind = 2


class J3(
    Handler,
    metaclass=type,
):
    kind = 3


class J4(
    Handler,
    metaclass=type,
):
    kind = 4


class J5(
    Handler,
    metaclass=type,
):
    kind = 5


class J6(
    Handler,
    metaclass=type,
):
    kind = 6


class J7(
    Handler,
    metaclass=type,
):
    kind = 7


class J8(
    Handler,
    metaclass=type,
):
    kind = 8


class J9(
    Handler,
    metaclass=type,
):
    kind = 9


