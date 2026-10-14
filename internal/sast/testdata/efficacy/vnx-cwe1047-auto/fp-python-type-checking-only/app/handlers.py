from __future__ import annotations

import typing as t

from .context import RequestContext

if t.TYPE_CHECKING:
    from .server import Server


def handle(server: Server, raw: bytes) -> RequestContext:
    return RequestContext(server, raw)
