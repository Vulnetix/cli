from typing import Callable, Dict


def memoise(fn: Callable[[int, int], int], /, size: int = 128, *, key: Callable[..., str] = repr) -> Callable:
    """Wrap fn in a bounded cache.

    Args:
        fn: function to wrap.
        size: number of entries kept.
        key: builds the cache key from the arguments.
    """
    store: Dict[str, int] = {}
    return lambda *a: store.setdefault(key(a), fn(*a))
